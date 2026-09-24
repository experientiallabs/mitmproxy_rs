use mitmproxy::intercept_conf::InterceptConf;
use pyo3::exceptions::PyValueError;

#[cfg(target_os = "linux")]
use mitmproxy::packet_sources::linux::LinuxConf;
#[cfg(target_os = "macos")]
use mitmproxy::packet_sources::macos::{MacosCommand, MacosConf};
#[cfg(windows)]
use mitmproxy::packet_sources::windows::WindowsConf;

use pyo3::prelude::*;
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, IntoRawFd};

use crate::server::base::Server;
use tokio::sync::mpsc;

#[cfg(target_os = "macos")]
type LocalCommand = MacosCommand;
#[cfg(not(target_os = "macos"))]
type LocalCommand = InterceptConf;

#[pyclass(module = "mitmproxy_rs.local")]
#[derive(Debug)]
pub struct LocalRedirector {
    server: Server,
    conf_tx: mpsc::UnboundedSender<LocalCommand>,
    spec: String,
    #[cfg(target_os = "macos")]
    control_transferred: bool,
}

impl LocalRedirector {
    pub fn new(server: Server, conf_tx: mpsc::UnboundedSender<LocalCommand>) -> Self {
        Self {
            server,
            conf_tx,
            spec: "inactive".to_string(),
            #[cfg(target_os = "macos")]
            control_transferred: false,
        }
    }
}

#[pymethods]
impl LocalRedirector {
    /// Check packaged and installed macOS bundle contents without installing or launching.
    #[cfg(target_os = "macos")]
    #[staticmethod]
    fn installation_is_current(py: Python<'_>) -> PyResult<bool> {
        Ok(macos::bundle_matches(
            &macos::archive_path(py)?,
            std::path::Path::new("/Applications"),
        )?)
    }

    /// Return a textual description of the given spec,
    /// or raise a ValueError if the spec is invalid.
    #[staticmethod]
    fn describe_spec(spec: &str) -> PyResult<String> {
        InterceptConf::try_from(spec)
            .map(|conf| conf.description())
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Set a new intercept spec.
    pub fn set_intercept(&mut self, spec: String) -> PyResult<()> {
        #[cfg(target_os = "macos")]
        if self.control_transferred {
            return Err(PyValueError::new_err(
                "The watchdog owns the control socket.",
            ));
        }
        let conf = InterceptConf::try_from(spec.as_str())?;
        self.spec = spec;
        #[cfg(target_os = "macos")]
        let conf = MacosCommand::SetIntercept(conf);
        self.conf_tx
            .send(conf)
            .map_err(crate::util::event_queue_unavailable)?;
        Ok(())
    }

    /// Transfer exclusive control writes to a Python socket owned by a watchdog.
    /// This awaits earlier configurations and disables subsequent set_intercept calls.
    #[cfg(target_os = "macos")]
    fn take_control_socket<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if self.control_transferred {
            return Err(PyValueError::new_err(
                "The watchdog already owns the control socket.",
            ));
        }
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.conf_tx
            .send(MacosCommand::TakeControl(reply))
            .map_err(crate::util::event_queue_unavailable)?;
        self.control_transferred = true;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fd = receiver
                .await
                .map_err(|_| anyhow::anyhow!("Control transfer failed."))?;
            Python::attach(|py| -> PyResult<Py<PyAny>> {
                let kwargs = pyo3::types::PyDict::new(py);
                kwargs.set_item("fileno", fd.as_raw_fd())?;
                let socket = py
                    .import("socket")?
                    .getattr("socket")?
                    .call((), Some(&kwargs))?;
                let _ = fd.into_raw_fd(); // The Python socket now owns the descriptor, including cancellation.
                Ok(socket.unbind())
            })
        })
    }

    /// Close the OS proxy server.
    pub fn close(&mut self) {
        self.server.close()
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Returns a `str` describing why local redirect mode is unavailable, or `None` if it is available.
    ///
    /// Reasons for unavailability may be an unsupported platform, or missing privileges.
    #[staticmethod]
    pub fn unavailable_reason() -> Option<String> {
        #[cfg(any(windows, target_os = "macos"))]
        return None;

        #[cfg(target_os = "linux")]
        if nix::unistd::geteuid().is_root() {
            None
        } else {
            Some("mitmproxy is not running as root.".to_string())
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        Some(format!(
            "Local redirect mode is not supported on {}",
            std::env::consts::OS
        ))
    }

    pub fn __repr__(&self) -> String {
        format!("Local Redirector({})", self.spec)
    }
}

/// Start an OS-level proxy to intercept traffic from the current machine.
///
/// - `handle_tcp_stream`: An async function that will be called for each new TCP `Stream`.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
///
/// *Availability: Windows, Linux, and macOS*
#[pyfunction]
#[allow(unused_variables)]
pub fn start_local_redirector(
    py: Python<'_>,
    handle_tcp_stream: Py<PyAny>,
    handle_udp_stream: Py<PyAny>,
) -> PyResult<Bound<'_, PyAny>> {
    #[cfg(windows)]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_windows")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = WindowsConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "linux")]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_linux")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = LinuxConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "macos")]
    {
        let redirector_tar = macos::archive_path(py)?;
        let copy_task = macos::copy_redirector_app(redirector_tar)?;
        let conf = MacosConf;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(copy_task) = copy_task {
                tokio::task::spawn_blocking(copy_task)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to copy: {e}"))??;
            }
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        LocalRedirector::unavailable_reason(),
    ))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::{Context, Result};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::{env, fs};

    pub(super) fn archive_path(py: Python<'_>) -> PyResult<PathBuf> {
        let filename = py.import("mitmproxy_macos")?.filename()?;
        Ok(Path::new(filename.to_str()?)
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?
            .join("Mitmproxy Redirector.app.tar"))
    }

    /// Compare bundle bytes so reinstalling a wheel never reinstalls an identical app.
    pub(super) fn bundle_matches(archive: &Path, applications: &Path) -> Result<bool> {
        let mut archive = tar::Archive::new(fs::File::open(archive)?);
        let mut files = 0;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let relative = entry.path()?;
            if !relative.starts_with("Mitmproxy Redirector.app")
                || relative
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                anyhow::bail!("invalid redirector archive path");
            }
            let destination = applications.join(&relative);
            let metadata = match fs::symlink_metadata(&destination) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if entry.header().entry_type().is_dir() {
                if !metadata.is_dir() {
                    return Ok(false);
                }
                continue;
            }
            if !entry.header().entry_type().is_file()
                || !metadata.is_file()
                || metadata.len() != entry.size()
            {
                return Ok(false);
            }
            let mut installed = fs::File::open(destination)?;
            let mut expected = [0_u8; 16384];
            let mut actual = [0_u8; 16384];
            loop {
                let count = entry.read(&mut expected)?;
                if count == 0 {
                    break;
                }
                installed.read_exact(&mut actual[..count])?;
                if expected[..count] != actual[..count] {
                    return Ok(false);
                }
            }
            files += 1;
        }
        Ok(files > 0)
    }

    /// Ensure "Mitmproxy Redirector.app" is installed into /Applications and up-to-date.
    pub(super) fn copy_redirector_app(
        redirector_tar: PathBuf,
    ) -> PyResult<Option<impl FnOnce() -> Result<()>>> {
        if env::var_os("MITMPROXY_KEEP_REDIRECTOR").is_some_and(|x| x == "1") {
            log::info!("Using existing mitmproxy redirector app.");
            return Ok(None);
        }

        if !redirector_tar.exists() {
            return Err(anyhow::anyhow!("{} does not exist", redirector_tar.display()).into());
        }
        if bundle_matches(&redirector_tar, Path::new("/Applications"))? {
            log::debug!("Existing mitmproxy redirector app is up-to-date.");
            return Ok(None);
        }
        log::info!("Installing packaged mitmproxy redirector app...");

        Ok(Some(move || {
            let archive_file = fs::File::open(redirector_tar)?;
            let mut archive = tar::Archive::new(archive_file);
            let destination_path = Path::new("/Applications/Mitmproxy Redirector.app/");
            if destination_path.exists() {
                // archive.unpack with overwrite does not work, so we do this.
                fs::remove_dir_all(destination_path)
                    .context("failed to remove existing mitmproxy redirector app")?;
            }
            archive
                .unpack(destination_path.parent().unwrap())
                .context("failed to unpack redirector")
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn installed_bundle_identity_ignores_timestamps_but_checks_every_file() -> Result<()> {
            let directory = tempfile::tempdir()?;
            let archive = directory.path().join("redirector.tar");
            let member = "Mitmproxy Redirector.app/Contents/Info.plist";
            let payload = b"signed app bytes";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(100);
            header.set_cksum();
            let mut builder = tar::Builder::new(fs::File::create(&archive)?);
            builder.append_data(&mut header, member, &payload[..])?;
            builder.finish()?;
            let applications = directory.path().join("Applications");
            assert!(!bundle_matches(&archive, &applications)?);
            let installed = applications.join(member);
            fs::create_dir_all(installed.parent().unwrap())?;
            fs::write(&installed, payload)?;
            assert!(bundle_matches(&archive, &applications)?);
            fs::File::open(&archive)?.set_modified(std::time::SystemTime::UNIX_EPOCH)?;
            assert!(bundle_matches(&archive, &applications)?);
            fs::write(&installed, b"changed app data")?;
            assert!(!bundle_matches(&archive, &applications)?);
            fs::remove_file(&installed)?;
            std::os::unix::fs::symlink(&archive, &installed)?;
            assert!(!bundle_matches(&archive, &applications)?);
            Ok(())
        }
    }
}
