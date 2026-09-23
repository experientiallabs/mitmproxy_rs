use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};

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
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct MacosConf;

/// Serialize configuration and control ownership transfer on the native loop.
pub enum MacosCommand {
    SetIntercept(InterceptConf),
    TakeControl(oneshot::Sender<OwnedFd>),
}

impl From<InterceptConf> for MacosCommand {
    fn from(conf: InterceptConf) -> Self {
        Self::SetIntercept(conf)
    }
}

async fn start_redirector(listener_addr: String) -> Result<()> {
    log::debug!("Starting redirector app...");
    let redirector_process =
        Command::new("/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector")
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
    type Data = UnboundedSender<MacosCommand>;

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

        start_redirector(listener_addr).await?;

        log::debug!("Waiting for control channel...");
        // XXX: Saw some hangs here during development, not sure why.
        let control_channel = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to macOS system extension")??
            .0;
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
            },
            conf_tx,
        ))
    }
}

pub struct MacOsTask {
    control_channel: UnixStream,
    listener: UnixListener,
    connections: JoinSet<Result<()>>,
    transport_events_tx: Sender<TransportEvent>,
    conf_rx: UnboundedReceiver<MacosCommand>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());
        let mut transferred = false;

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                _ = control_channel.next() => {
                    // No messages expected here at the moment.
                    bail!("macOS System Extension shut down.")
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
                Some(command) = self.conf_rx.recv() => {
                    match command {
                        MacosCommand::SetIntercept(conf) if !transferred => {
                            let msg = ipc::InterceptConf::from(conf).encode_to_vec();
                            control_channel.send(Bytes::from(msg)).await.context("Failed to write to control channel")?;
                        }
                        MacosCommand::TakeControl(reply) if !transferred => {
                            // All earlier frames have been flushed. The watchdog becomes
                            // the only writer, so an owner crash cannot truncate its frame.
                            let fd = control_channel.get_ref().as_fd().try_clone_to_owned()?;
                            if reply.send(fd).is_ok() {
                                transferred = true;
                            }
                        }
                        _ => bail!("macOS control channel ownership already transferred"),
                    }
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
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
                packet = stream.next(), if state.packet_queue_len() < 10 => {
                    let Some(packet) = packet else {
                        state.close();
                        break;
                    };
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
                            stream.send(write_buf.split().freeze()).await.context("IPC write error")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn udp_flow() -> UdpFlow {
        UdpFlow {
            local_address: Some(ipc::Address {
                host: "127.0.0.1".into(),
                port: 53001,
            }),
            tunnel_info: Some(ipc::TunnelInfo {
                pid: Some(42),
                process_name: None,
            }),
        }
    }

    fn datagram() -> Bytes {
        Bytes::from(
            ipc::UdpPacket {
                data: Bytes::from_static(b"query"),
                remote_address: Some(ipc::Address {
                    host: "127.0.0.1".into(),
                    port: 53,
                }),
            }
            .encode_to_vec(),
        )
    }

    #[tokio::test]
    async fn control_transfer_flushes_configuration_and_leaves_watchdog_socket_alive() {
        let (extension, proxy) = UnixStream::pair().unwrap();
        let path = format!(
            "/tmp/exp-control-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let (conf_tx, conf_rx) = unbounded_channel();
        let (events, _received) = mpsc::channel(1);
        let (owner, shutdown) = shutdown::channel();
        let task = tokio::spawn(
            MacOsTask {
                control_channel: proxy,
                listener,
                connections: JoinSet::new(),
                transport_events_tx: events,
                conf_rx,
                shutdown,
            }
            .run(),
        );
        conf_tx
            .send(MacosCommand::SetIntercept(
                InterceptConf::try_from("0,!0").unwrap(),
            ))
            .unwrap();
        let (reply, receiver) = oneshot::channel();
        conf_tx.send(MacosCommand::TakeControl(reply)).unwrap();
        let owned = timeout(Duration::from_secs(1), receiver)
            .await
            .unwrap()
            .unwrap();
        let mut extension = Framed::new(extension, LengthDelimitedCodec::new());
        let first = extension.next().await.unwrap().unwrap();
        assert_eq!(
            ipc::InterceptConf::decode(first).unwrap().actions,
            ["0", "!0"]
        );
        owner.send(()).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // The independent owner can still disable the extension after the native task exits.
        let std_socket = std::os::unix::net::UnixStream::from(owned);
        let mut watchdog = Framed::new(
            UnixStream::from_std(std_socket).unwrap(),
            LengthDelimitedCodec::new(),
        );
        watchdog
            .send(Bytes::from(
                ipc::InterceptConf {
                    actions: vec!["0".into(), "!0".into()],
                }
                .encode_to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(
            ipc::InterceptConf::decode(extension.next().await.unwrap().unwrap())
                .unwrap()
                .actions,
            ["0", "!0"]
        );
    }

    #[tokio::test]
    async fn udp_eof_before_first_datagram_releases_task() {
        let (extension, proxy) = UnixStream::pair().unwrap();
        let (events, mut received) = mpsc::channel(1);
        let (_owner, shutdown) = shutdown::channel();
        let task =
            tokio::spawn(ConnectionTask::new(proxy, events, shutdown).handle_udp(udp_flow()));
        drop(extension);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(received.recv().await.is_none());
    }

    #[tokio::test]
    async fn udp_eof_after_datagram_wakes_pending_reader() {
        let (extension, proxy) = UnixStream::pair().unwrap();
        let (events, mut received) = mpsc::channel(1);
        let (_owner, shutdown) = shutdown::channel();
        let task =
            tokio::spawn(ConnectionTask::new(proxy, events, shutdown).handle_udp(udp_flow()));
        let mut extension = Framed::new(extension, LengthDelimitedCodec::new());
        extension.send(datagram()).await.unwrap();
        let TransportEvent::ConnectionEstablished {
            connection_id,
            command_tx: Some(commands),
            ..
        } = received.recv().await.unwrap()
        else {
            panic!("missing connection")
        };
        let (tx, rx) = oneshot::channel();
        commands
            .send(TransportCommand::ReadData(connection_id, 0, tx))
            .unwrap();
        assert_eq!(rx.await.unwrap(), b"query");
        let (tx, rx) = oneshot::channel();
        commands
            .send(TransportCommand::ReadData(connection_id, 0, tx))
            .unwrap();
        drop(extension);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(rx.await.is_err());
        assert!(commands.is_closed());
    }

    #[tokio::test]
    async fn udp_stays_open_while_owner_exists_and_closes_on_shutdown() {
        let (extension, proxy) = UnixStream::pair().unwrap();
        let (events, _received) = mpsc::channel(1);
        let (owner, shutdown) = shutdown::channel();
        let mut task =
            tokio::spawn(ConnectionTask::new(proxy, events, shutdown).handle_udp(udp_flow()));
        assert!(timeout(Duration::from_millis(20), &mut task).await.is_err());
        owner.send(()).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut extension = Framed::new(extension, LengthDelimitedCodec::new());
        assert!(extension.next().await.is_none());
    }
}
