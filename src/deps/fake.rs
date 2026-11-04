//! A local stand-in for OSV.dev, deps.dev and Packagist in unit tests, so none of
//! them touches the network. Every request is recorded; `handler` answers it.

use percent_encoding::percent_decode_str;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Request {
    /// As sent, percent-encoding included.
    pub path: String,
    pub body: String,
}

impl Request {
    pub fn decoded_path(&self) -> String {
        percent_decode_str(&self.path)
            .decode_utf8_lossy()
            .into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

pub struct Reply {
    status: u16,
    body: String,
}

pub fn reply(status: u16, body: impl Into<String>) -> Reply {
    Reply {
        status,
        body: body.into(),
    }
}

pub fn json(value: &serde_json::Value) -> Reply {
    reply(200, value.to_string())
}

pub struct Server {
    /// `http://127.0.0.1:<port>`
    pub url: String,
    log: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    pub fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }
}

pub fn serve(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let (seen, handler) = (Arc::clone(&log), Arc::new(handler));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, handler) = (Arc::clone(&seen), Arc::clone(&handler));
            std::thread::spawn(move || answer(stream, &seen, &*handler));
        }
    });
    Server { url, log }
}

fn answer(
    mut stream: std::net::TcpStream,
    seen: &Mutex<Vec<Request>>,
    handler: &dyn Fn(&Request) -> Reply,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let path = parts.nth(1).unwrap_or("");
    let mut length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap() <= 2 {
            break;
        }
        if let Some((k, v)) = header.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            length = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request = Request {
        path: path.into(),
        body: String::from_utf8(body).unwrap(),
    };
    seen.lock().unwrap().push(request.clone());
    let reply = handler(&request);
    // A client that gave up (timeout test) is not an error here.
    let _ = write!(
        stream,
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply.status,
        reply.body.len(),
        reply.body
    );
}
