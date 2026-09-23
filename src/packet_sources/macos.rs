use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::process::CommandExt;

use crate::messages::{ConnectionIdGenerator, TransportCommand, TransportEvent, TunnelInfo};

use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::{NewFlow, TcpFlow, UdpFlow};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use anyhow::{Context, Result, bail};
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::Message;
use prost::bytes::Bytes;
use prost::bytes::BytesMut;

use std::process::Stdio;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::network::udp::ConnectionState;
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct MacosConf {
    capture_domains: Option<Vec<String>>,
}

pub type CaptureResult = Option<std::result::Result<(), String>>;

pub struct MacosData {
    pub conf_tx: UnboundedSender<InterceptConf>,
    pub capture_result: Option<watch::Receiver<CaptureResult>>,
}

impl MacosConf {
    pub fn new(capture_domains: Option<Vec<String>>) -> Result<Self> {
        if let Some(domains) = &capture_domains {
            validate_capture_domains(domains)?;
        }
        Ok(Self { capture_domains })
    }
}

fn validate_capture_domains(domains: &[String]) -> Result<()> {
    if domains.is_empty() || domains.len() > 32 {
        bail!("Capture requires between 1 and 32 provider hostnames.");
    }
    for domain in domains {
        let labels: Vec<_> = domain.split('.').collect();
        if domain.len() > 253
            || labels.len() < 2
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
            || labels.last().is_some_and(|label| {
                matches!(
                    *label,
                    "localhost" | "local" | "internal" | "test" | "invalid"
                ) || label.bytes().all(|c| c.is_ascii_digit())
            })
        {
            bail!("Capture requires literal lowercase public DNS hostnames.");
        }
    }
    Ok(())
}

const CAPTURE_START_TIMEOUT: Duration = Duration::from_secs(160);
const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const REDIRECTOR_EXECUTABLE: &str =
    "/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector";

struct CaptureSupervisor {
    child: Option<Child>,
    stdout: Option<ChildStdout>,
    result: watch::Sender<CaptureResult>,
}

impl CaptureSupervisor {
    async fn start(
        domains: &[String],
        listener: &str,
    ) -> Result<(Self, watch::Receiver<CaptureResult>)> {
        let mut command = Command::new(REDIRECTOR_EXECUTABLE);
        command.args(["--capture-safety", &domains.join(","), listener]);
        Self::start_command(command, CAPTURE_START_TIMEOUT).await
    }

    async fn start_command(
        mut command: Command,
        deadline: Duration,
    ) -> Result<(Self, watch::Receiver<CaptureResult>)> {
        // Keep terminal signals away from the helper so it can detach after owner death.
        command.as_std_mut().process_group(0);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to launch Capture supervisor.")?;
        let stdout = child
            .stdout
            .take()
            .context("Capture supervisor has no status pipe.")?;
        let (result, receiver) = watch::channel(None);
        let mut supervisor = Self {
            child: Some(child),
            stdout: Some(stdout),
            result,
        };
        let mut ready = [0u8; b"CAPTURE_READY\n".len()];
        let started = timeout(
            deadline,
            supervisor.stdout.as_mut().unwrap().read_exact(&mut ready),
        )
        .await;
        if !matches!(started, Ok(Ok(_))) || ready != *b"CAPTURE_READY\n" {
            let _ = supervisor
                .finish(
                    Err(anyhow::anyhow!("Capture supervisor did not become ready.")),
                    CAPTURE_STOP_TIMEOUT,
                )
                .await;
            bail!("Capture supervisor did not become ready.");
        }
        Ok((supervisor, receiver))
    }

    async fn exited(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.wait().await;
        }
    }

    async fn finish(&mut self, run_result: Result<()>, deadline: Duration) -> Result<()> {
        let child = self
            .child
            .take()
            .context("Capture supervisor already closed.")?;
        let stdout = self
            .stdout
            .take()
            .context("Capture supervisor status pipe already closed.")?;
        let result_tx = self.result.clone();
        // A sibling task failure may abort this task; the owned cleanup must still finish.
        tokio::spawn(async move {
            let result = stop_capture_child(child, stdout, deadline)
                .await
                .and(run_result);
            result_tx.send_replace(Some(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
            ));
            result
        })
        .await
        .context("Capture cleanup task did not finish.")?
    }
}

impl Drop for CaptureSupervisor {
    fn drop(&mut self) {
        let (Some(mut child), Some(stdout)) = (self.child.take(), self.stdout.take()) else {
            return;
        };
        // EOF tells the independently running helper to detach even if our task is aborted.
        drop(child.stdin.take());
        let result = self.result.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let stopped = stop_capture_child(child, stdout, CAPTURE_STOP_TIMEOUT).await;
                result.send_replace(Some(stopped.map_err(|error| error.to_string())));
            });
        } else {
            result.send_replace(Some(Err("Capture cleanup could not be confirmed.".into())));
        }
    }
}

async fn stop_capture_child(
    mut child: Child,
    mut stdout: ChildStdout,
    deadline: Duration,
) -> Result<()> {
    drop(child.stdin.take());
    let mut output = Vec::new();
    let stopped = timeout(deadline, async {
        let mut bounded = (&mut stdout).take(256);
        let (_, status) = tokio::try_join!(bounded.read_to_end(&mut output), child.wait())?;
        Ok::<_, std::io::Error>(status)
    })
    .await;
    let detached = output.starts_with(b"CAPTURE_STOPPED\n");
    let status = match stopped {
        Ok(Ok(status)) => status,
        _ => {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(2), child.wait()).await;
            if detached {
                bail!("Capture stopped, but its final DNS check did not finish.");
            }
            bail!("Capture cleanup could not be confirmed.");
        }
    };
    if !detached {
        bail!("Capture cleanup could not be confirmed.");
    }
    if output
        .windows(b"CAPTURE_DNS_UNAVAILABLE\n".len())
        .any(|line| line == b"CAPTURE_DNS_UNAVAILABLE\n")
    {
        bail!("Capture stopped, but system DNS is unavailable.");
    }
    if !status.success() || output != b"CAPTURE_STOPPED\n" {
        bail!("Capture stopped, but its helper failed its final checks.");
    }
    Ok(())
}

async fn start_redirector(listener_addr: String) -> Result<()> {
    log::debug!("Starting redirector app...");
    let redirector_process = Command::new(REDIRECTOR_EXECUTABLE)
        .arg(listener_addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to launch macos-redirector app.")?;

    let output = redirector_process.wait_with_output().await?;
    if !output.stdout.is_empty() {
        log::info!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    if !output.stderr.is_empty() {
        log::error!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.status.success() {
        bail!(
            "macos-redirector exited with status {:?}",
            output.status.code()
        );
    }
    log::debug!("Redirector app exited successfully.");
    Ok(())
}

impl PacketSourceConf for MacosConf {
    type Task = MacOsTask;
    type Data = MacosData;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        _transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let listener_addr = format!("/tmp/mitmproxy-{}", std::process::id());
        let listener = UnixListener::bind(&listener_addr)?;

        let (mut supervisor, capture_result) = if let Some(domains) = self.capture_domains {
            let (supervisor, result) = CaptureSupervisor::start(&domains, &listener_addr).await?;
            (Some(supervisor), Some(result))
        } else {
            start_redirector(listener_addr).await?;
            (None, None)
        };

        log::debug!("Waiting for control channel...");
        // XXX: Saw some hangs here during development, not sure why.
        let connected = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to macOS system extension")
            .and_then(|result| result.map_err(Into::into));
        let control_channel = match connected {
            Ok((channel, _)) => channel,
            Err(error) => {
                if let Some(supervisor) = supervisor.as_mut() {
                    let _ = supervisor.finish(Err(error), CAPTURE_STOP_TIMEOUT).await;
                }
                bail!("failed to establish connection to macOS system extension");
            }
        };
        log::debug!("Control channel connected.");

        let (conf_tx, conf_rx) = unbounded_channel();
        Ok((
            MacOsTask {
                control_channel,
                listener,
                connections: JoinSet::new(),
                transport_events_tx,
                conf_rx,
                shutdown,
                supervisor,
            },
            MacosData {
                conf_tx,
                capture_result,
            },
        ))
    }
}

pub struct MacOsTask {
    control_channel: UnixStream,
    listener: UnixListener,
    connections: JoinSet<Result<()>>,
    transport_events_tx: Sender<TransportEvent>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
    supervisor: Option<CaptureSupervisor>,
}

impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

        let result = loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break Ok(()),
                _ = async {
                    match self.supervisor.as_mut() {
                        Some(supervisor) => supervisor.exited().await,
                        None => std::future::pending().await,
                    }
                } => break Err(anyhow::anyhow!("Capture supervisor exited unexpectedly.")),
                _ = control_channel.next() => {
                    // No messages expected here at the moment.
                    break Err(anyhow::anyhow!("macOS System Extension shut down."));
                },
                Some(task) = self.connections.join_next() => {
                    match task {
                        Ok(Ok(())) => (),
                        Ok(Err(e)) => log::error!("Connection task failure: {e:?}"),
                        Err(e) => log::error!("Connection task panic: {e:?}"),
                    }
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let task = ConnectionTask::new(
                                stream,
                                self.transport_events_tx.clone(),
                                self.shutdown.clone(),
                            );
                            self.connections.spawn(task.run());
                        },
                        Err(e) => log::error!("Error accepting connection from macos-redirector: {e}")
                    }
                },
                // pipe through changes to the intercept list
                Some(conf) = self.conf_rx.recv() => {
                    let msg = ipc::InterceptConf::from(conf).encode_to_vec();
                    if let Err(error) = control_channel.send(Bytes::from(msg)).await.context("Failed to write to control channel") {
                        break Err(error);
                    }
                },
            }
        };

        drop(control_channel);
        self.connections.shutdown().await;
        if let Some(supervisor) = self.supervisor.as_mut() {
            return supervisor.finish(result, CAPTURE_STOP_TIMEOUT).await;
        }
        log::info!("Macos OS proxy task shutting down.");
        result
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn helper(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn capture_domains_are_bounded_public_ascii_names() {
        assert!(MacosConf::new(None).is_ok());
        assert!(MacosConf::new(Some(vec!["chatgpt.com".into(), "api.openai.com".into()])).is_ok());
        assert!(MacosConf::new(Some(vec!["api.openai.com".into(); 32])).is_ok());
        for domains in [
            vec![],
            vec!["chatgpt.com".into(); 33],
            vec!["localhost".into()],
            vec!["app.local".into()],
            vec!["127.0.0.1".into()],
            vec!["chatgpt.com,other.com".into()],
            vec!["https://chatgpt.com".into()],
            vec!["CHATGPT.COM".into()],
            vec!["äpp.example.com".into()],
            vec!["bad-.example.com".into()],
            vec![format!("{}.com", "x".repeat(64))],
            vec![format!(
                "{}.{}.{}.{}.com",
                "x".repeat(63),
                "x".repeat(63),
                "x".repeat(63),
                "x".repeat(63)
            )],
        ] {
            assert!(MacosConf::new(Some(domains)).is_err());
        }
    }

    #[tokio::test]
    async fn capture_child_is_retained_until_owner_closes_stdin() {
        let command = helper(
            "printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'",
        );
        let (mut supervisor, result) =
            CaptureSupervisor::start_command(command, Duration::from_secs(5))
                .await
                .unwrap();
        assert!(
            supervisor
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        assert!(result.borrow().is_none());
        supervisor
            .finish(Ok(()), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(*result.borrow(), Some(Ok(())));
        assert!(supervisor.child.is_none());
    }

    #[tokio::test]
    async fn capture_owner_drop_closes_stdin_and_waits_for_detach() {
        let command = helper(
            "printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'",
        );
        let (supervisor, mut result) =
            CaptureSupervisor::start_command(command, Duration::from_secs(5))
                .await
                .unwrap();
        drop(supervisor);
        timeout(Duration::from_secs(5), result.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*result.borrow(), Some(Ok(())));
    }

    #[tokio::test]
    async fn capture_cleanup_survives_cancelled_wait() {
        let command = helper(
            "printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'",
        );
        let (mut supervisor, mut result) =
            CaptureSupervisor::start_command(command, Duration::from_secs(5))
                .await
                .unwrap();
        let mut closing = Box::pin(supervisor.finish(Ok(()), Duration::from_secs(5)));
        assert!(futures_util::poll!(&mut closing).is_pending());
        drop(closing);
        drop(supervisor);
        timeout(Duration::from_secs(5), async {
            while result.borrow().is_none() {
                result.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(*result.borrow(), Some(Ok(())));
    }

    #[tokio::test]
    async fn capture_startup_eof_and_invalid_ready_are_errors() {
        for script in ["exit 0", "printf 'NOT_CAPTURE_READY\\n'"] {
            assert!(
                CaptureSupervisor::start_command(helper(script), Duration::from_secs(5))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn capture_startup_timeout_closes_owner_pipe() {
        let command = helper("IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'");
        let result = timeout(
            Duration::from_secs(5),
            CaptureSupervisor::start_command(command, Duration::from_millis(25)),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn capture_cleanup_requires_stopped_ack_and_successful_exit() {
        for (ending, expected) in [
            ("exit 0", "Capture cleanup could not be confirmed."),
            (
                "printf 'CAPTURE_STOPPED\\n'; exit 1",
                "Capture stopped, but its helper failed its final checks.",
            ),
            (
                "printf 'CAPTURE_STOPPED\\nCAPTURE_DNS_UNAVAILABLE\\n'; exit 1",
                "Capture stopped, but system DNS is unavailable.",
            ),
        ] {
            let script = format!("printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; {ending}");
            let (mut supervisor, result) =
                CaptureSupervisor::start_command(helper(&script), Duration::from_secs(5))
                    .await
                    .unwrap();
            let error = supervisor
                .finish(Ok(()), Duration::from_secs(5))
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(*result.borrow(), Some(Err(expected.into())));
        }
    }

    #[tokio::test]
    async fn capture_cleanup_timeout_kills_owned_child_and_reports_unconfirmed() {
        let command =
            helper("printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; while :; do :; done");
        let (mut supervisor, result) =
            CaptureSupervisor::start_command(command, Duration::from_secs(5))
                .await
                .unwrap();
        let stopped = timeout(
            Duration::from_secs(5),
            supervisor.finish(Ok(()), Duration::from_millis(25)),
        )
        .await
        .unwrap();
        assert_eq!(
            stopped.unwrap_err().to_string(),
            "Capture cleanup could not be confirmed."
        );
        assert_eq!(
            *result.borrow(),
            Some(Err("Capture cleanup could not be confirmed.".into()))
        );
        assert!(supervisor.child.is_none());
    }

    #[tokio::test]
    async fn capture_reports_dns_timeout_separately_after_confirmed_detach() {
        let command = helper(
            "printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'; while :; do :; done",
        );
        let (mut supervisor, _) = CaptureSupervisor::start_command(command, Duration::from_secs(5))
            .await
            .unwrap();
        let error = supervisor
            .finish(Ok(()), Duration::from_millis(25))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Capture stopped, but its final DNS check did not finish."
        );
    }

    #[tokio::test]
    async fn capture_preserves_backend_failure_after_confirmed_detach() {
        let command = helper(
            "printf 'CAPTURE_READY\\n'; IFS= read -r owner || :; printf 'CAPTURE_STOPPED\\n'",
        );
        let (mut supervisor, result) =
            CaptureSupervisor::start_command(command, Duration::from_secs(5))
                .await
                .unwrap();
        let error = supervisor
            .finish(
                Err(anyhow::anyhow!("synthetic control failure")),
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "synthetic control failure");
        assert_eq!(
            *result.borrow(),
            Some(Err("synthetic control failure".into()))
        );
    }
}

struct ConnectionTask {
    stream: UnixStream,
    events: Sender<TransportEvent>,
    shutdown: shutdown::Receiver,
}

impl ConnectionTask {
    pub fn new(
        stream: UnixStream,
        events: Sender<TransportEvent>,
        shutdown: shutdown::Receiver,
    ) -> Self {
        Self {
            stream,
            events,
            shutdown,
        }
    }
    async fn run(mut self) -> Result<()> {
        let new_flow = {
            let len = self
                .stream
                .read_u32()
                .await
                .context("Failed to read handshake.")? as usize;
            let mut buf = vec![0; len];
            self.stream
                .read_exact(&mut buf)
                .await
                .context("Failed to read handshake contents.")?;
            NewFlow::decode(buf.as_slice()).context("Invalid handshake IPC")?
        };

        match new_flow {
            NewFlow {
                message: Some(ipc::new_flow::Message::Tcp(tcp_flow)),
            } => self
                .handle_tcp(tcp_flow)
                .await
                .context("failed to handle TCP stream"),
            NewFlow {
                message: Some(ipc::new_flow::Message::Udp(udp_flow)),
            } => self
                .handle_udp(udp_flow)
                .await
                .context("failed to handle UDP stream"),
            _ => bail!("Received invalid IPC message: {new_flow:?}"),
        }
    }

    async fn handle_udp(mut self, flow: UdpFlow) -> Result<()> {
        // For UDP connections, we pass length-delimited protobuf messages over the unix socket
        // in both directions.
        let mut write_buf = BytesMut::new();
        let mut stream = Framed::new(self.stream, LengthDelimitedCodec::new());

        let tunnel_info = {
            let Some(tun) = flow.tunnel_info else {
                bail!("no tunnel info")
            };
            TunnelInfo::LocalRedirector {
                pid: tun.pid,
                process_name: tun.process_name,
                remote_endpoint: None,
            }
        };
        let local_address = {
            let Some(addr) = &flow.local_address else {
                bail!("no local address")
            };
            SocketAddr::try_from(addr)
                .with_context(|| format!("invalid local_address: {addr:?}"))?
        };
        let mut remote_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let (command_tx, mut command_rx) = unbounded_channel();

        let mut first_packet = Some((tunnel_info, local_address, command_tx));

        let mut state = ConnectionState::default();

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                Some(packet) = stream.next(), if state.packet_queue_len() < 10 => {
                    let packet = ipc::UdpPacket::decode(
                        packet.context("IPC read error")?
                    ).context("invalid IPC message")?;
                    let dst_addr = {
                        let Some(dst_addr) = &packet.remote_address else { bail!("no remote addr") };
                        SocketAddr::try_from(dst_addr).with_context(|| format!("invalid remote_address: {dst_addr:?}"))?
                    };

                    // We can only send ConnectionEstablished once we know the destination address.
                    if let Some((tunnel_info, local_address, command_tx)) = first_packet.take() {
                        remote_address = dst_addr;
                        self.events.send(TransportEvent::ConnectionEstablished {
                            connection_id: ConnectionIdGenerator::udp().next_id(),
                            src_addr: local_address,
                            dst_addr,
                            tunnel_info,
                            command_tx: Some(command_tx),
                        }).await?;
                    } else if remote_address != dst_addr {
                        bail!("UDP packet destinations do not match: {remote_address} -> {dst_addr}")
                    }
                    // TODO: Make ConnectionState accept Bytes, not Vec<u8>
                    state.add_packet(packet.data.to_vec());
                },
                Some(command) = command_rx.recv() => {
                    match command {
                        TransportCommand::ReadData(_, _, tx) => {
                            state.add_reader(tx);
                        },
                        TransportCommand::WriteData(_, data) => {
                            assert!(first_packet.is_none());
                            let packet = ipc::UdpPacket {
                                data: Bytes::from(data),
                                remote_address: Some(remote_address.into()),
                            };
                            write_buf.reserve(packet.encoded_len());
                            packet.encode(&mut write_buf)?;
                            // Awaiting here isn't ideal because it blocks reading, but what to do.
                            stream.send(write_buf.split().freeze()).await.ok();
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            tx.send(()).ok();
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            if !half_close {
                                state.close();
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_tcp(mut self, flow: TcpFlow) -> Result<()> {
        let mut write_buf = BytesMut::new();
        let mut drain_tx: Option<oneshot::Sender<()>> = None;
        let mut read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)> = None;

        let (command_tx, mut command_rx) = unbounded_channel();

        let remote = flow.remote_address.expect("no remote address");
        let src_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let dst_addr = SocketAddr::try_from(&remote)
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let tunnel_info = TunnelInfo::LocalRedirector {
            pid: flow.tunnel_info.as_ref().and_then(|t| t.pid),
            process_name: flow.tunnel_info.and_then(|t| t.process_name),
            remote_endpoint: Some((remote.host, remote.port as u16)),
        };

        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: ConnectionIdGenerator::tcp().next_id(),
                src_addr,
                dst_addr,
                tunnel_info,
                command_tx: Some(command_tx),
            })
            .await?;

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                Ok(()) = self.stream.writable(), if !write_buf.is_empty() => {
                    let Ok(_) = self.stream.write_buf(&mut write_buf).await else {
                        break;  // Client has disconnected.
                    };
                    if write_buf.is_empty()
                        && let Some(tx) = drain_tx.take() {
                            tx.send(()).ok();
                        }
                },
                Ok(()) = self.stream.readable(), if read_tx.is_some() => {
                    let (n, tx) = read_tx.take().unwrap();
                    let mut data = Vec::with_capacity(n);
                    self.stream.read_buf(&mut data).await.context("failed to read from socket")?;
                    tx.send(data).ok();
                },
                Some(command) = command_rx.recv() => {
                    match command {
                        TransportCommand::ReadData(_, n, tx) => {
                            assert!(read_tx.is_none());
                            read_tx = Some((n as usize, tx));
                        },
                        TransportCommand::WriteData(_, data) => {
                            write_buf.extend_from_slice(data.as_slice());
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            assert!(drain_tx.is_none());
                            if write_buf.is_empty() {
                                tx.send(()).ok();
                            } else {
                                drain_tx = Some(tx);
                            }
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            self.stream.flush().await.ok(); // supposedly this is a no-op on unix sockets.
                            self.stream.shutdown().await.ok();
                            if !half_close {
                                break;
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }
}
