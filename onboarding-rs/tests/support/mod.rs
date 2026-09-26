//! Shared test helpers: a scriptable mock admin HTTP server.
#![allow(dead_code)]

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One request the mock admin server received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub body: String,
    pub cookie: Option<String>,
    pub content_type: Option<String>,
}

/// Scripted response: status, body and optional `Set-Cookie`.
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub set_cookie: Option<String>,
}

impl Reply {
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Reply {
            status,
            body: body.to_string(),
            set_cookie: None,
        }
    }

    pub fn raw(status: u16, body: &str) -> Self {
        Reply {
            status,
            body: body.into(),
            set_cookie: None,
        }
    }
}

type Handler = dyn Fn(&Recorded) -> Reply + Send + Sync;

pub struct MockAdmin {
    pub base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
}

impl MockAdmin {
    pub fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let thread = {
            let server = Arc::clone(&server);
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);
                    let header = |name: &'static str| {
                        request
                            .headers()
                            .iter()
                            .find(|h| h.field.equiv(name))
                            .map(|h| h.value.to_string())
                    };
                    let recorded = Recorded {
                        method: request.method().to_string().to_uppercase(),
                        path: request.url().to_owned(),
                        body,
                        cookie: header("Cookie"),
                        content_type: header("Content-Type"),
                    };
                    let reply = handler(&recorded);
                    requests.lock().unwrap().push(recorded);
                    let mut response =
                        tiny_http::Response::from_string(reply.body).with_status_code(reply.status);
                    if let Some(cookie) = reply.set_cookie {
                        response.add_header(
                            tiny_http::Header::from_bytes("Set-Cookie", cookie).unwrap(),
                        );
                    }
                    let _ = request.respond(response);
                }
            })
        };
        MockAdmin {
            base_url: format!("http://127.0.0.1:{port}"),
            requests,
            server,
            thread: Some(thread),
        }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }
}

impl Drop for MockAdmin {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
