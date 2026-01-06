#![cfg(feature = "embedded")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use syftbox_sdk::syftbox::config::SyftboxRuntimeConfig;
use syftbox_sdk::syftbox::control::{is_syftbox_running, start_syftbox, stop_syftbox};

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct FakeHttpServer {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
    base_url: String,
}

impl FakeHttpServer {
    fn start() -> Self {
        let port = pick_free_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_task = stop.clone();
        let join = thread::spawn(move || {
            while !stop_task.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0_u8; 4096];
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");

                        let (status, body) = if path == "/healthz" {
                            ("200 OK", "ok")
                        } else {
                            ("404 Not Found", "not found")
                        };

                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });

        Self {
            stop,
            join: Some(join),
            base_url: format!("http://127.0.0.1:{port}"),
        }
    }

    fn url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn wait_until(mut check: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn embedded_backend_starts_and_stops() {
    let server = FakeHttpServer::start();
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let cp_port = pick_free_port();
    let client_url = format!("http://127.0.0.1:{cp_port}");
    let cfg_path = tmp.path().join("config.json");
    // Use forward slashes for JSON compatibility on Windows
    let data_dir_str = data_dir.display().to_string().replace('\\', "/");
    std::fs::write(
        &cfg_path,
        format!(
            r#"{{
  "data_dir": "{}",
  "email": "alice@example.com",
  "server_url": "{}",
  "client_url": "{}",
  "client_token": ""
}}"#,
            data_dir_str,
            server.url(),
            client_url
        ),
    )
    .unwrap();

    std::env::set_var("BV_SYFTBOX_BACKEND", "embedded");

    let runtime =
        SyftboxRuntimeConfig::new("alice@example.com", cfg_path.clone(), data_dir.clone());

    assert!(start_syftbox(&runtime).unwrap());
    assert!(
        wait_until(
            || is_syftbox_running(&runtime).unwrap_or(false),
            Duration::from_secs(2)
        ),
        "expected control plane to become reachable"
    );

    assert!(stop_syftbox(&runtime).unwrap());
    assert!(
        wait_until(
            || !is_syftbox_running(&runtime).unwrap_or(true),
            Duration::from_secs(2)
        ),
        "expected control plane to stop"
    );
}
