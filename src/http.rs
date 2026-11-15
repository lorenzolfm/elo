use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const HEAD_LENGTH_MAX: usize = 8 * 1024;

pub(crate) const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub(crate) const LISTEN_BACKLOG: u32 = 4;

pub(crate) const ACCEPT_ERROR_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

const HEAD_END: &[u8] = b"\r\n\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) target: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Response {
    Ok {
        content_type: &'static str,
        body: String,
    },
    BadRequest,
    NotFound,
    MethodNotAllowed {
        allow: &'static str,
    },
}

#[derive(Debug)]
enum HeadError {
    Io(std::io::Error),
    Closed,
    TooLong,
}

pub(crate) fn listen(
    address: std::net::SocketAddr,
) -> Result<tokio::net::TcpListener, std::io::Error> {
    let socket = match address {
        std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(LISTEN_BACKLOG)
}

pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    answer: impl Fn(Request<'_>) -> Response,
) -> std::convert::Infallible {
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let exchange = exchange(&mut stream, &answer);
                let _ = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await;
            }
            Err(_) => tokio::time::sleep(ACCEPT_ERROR_WAIT).await,
        }
    }
}

async fn exchange(
    stream: &mut tokio::net::TcpStream,
    answer: impl Fn(Request<'_>) -> Response,
) -> Result<(), std::io::Error> {
    let response = match read_head(stream).await {
        Ok(head) => match request(&head) {
            Some(request) => answer(request),
            None => Response::BadRequest,
        },
        Err(HeadError::TooLong) => Response::BadRequest,
        Err(HeadError::Closed) => return Ok(()),
        Err(HeadError::Io(error)) => return Err(error),
    };
    stream.write_all(&response.bytes()).await?;
    stream.shutdown().await
}

async fn read_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Vec<u8>, HeadError> {
    let mut buffer = vec![0; HEAD_LENGTH_MAX];
    let mut filled: usize = 0;
    loop {
        let read = stream
            .read(&mut buffer[filled..])
            .await
            .map_err(HeadError::Io)?;
        if read == 0 {
            return Err(HeadError::Closed);
        }
        let search_start = filled.saturating_sub(HEAD_END.len());
        filled += read;
        assert!(filled <= HEAD_LENGTH_MAX);
        let found = buffer[search_start..filled]
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END);
        if let Some(position) = found {
            buffer.truncate(search_start + position + HEAD_END.len());
            return Ok(buffer);
        }
        if filled == HEAD_LENGTH_MAX {
            return Err(HeadError::TooLong);
        }
    }
}

fn request(head: &[u8]) -> Option<Request<'_>> {
    assert!(head.ends_with(HEAD_END));
    let line_end = head.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if method.is_empty() {
        return None;
    }
    if !method.bytes().all(token_byte) {
        return None;
    }
    if target.is_empty() {
        return None;
    }
    if !target.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return None;
    }
    Some(Request { method, target })
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

impl Response {
    fn bytes(&self) -> Vec<u8> {
        let (status, headers, body) = match self {
            Response::Ok { content_type, body } => {
                assert!(!content_type.contains(['\r', '\n']), "{content_type:?}");
                (
                    "200 OK",
                    format!("Content-Type: {content_type}\r\n"),
                    body.as_str(),
                )
            }
            Response::BadRequest => ("400 Bad Request", String::new(), ""),
            Response::NotFound => ("404 Not Found", String::new(), ""),
            Response::MethodNotAllowed { allow } => {
                assert!(!allow.contains(['\r', '\n']), "{allow:?}");
                ("405 Method Not Allowed", format!("Allow: {allow}\r\n"), "")
            }
        };
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn answer(request: super::Request<'_>) -> super::Response {
        super::Response::Ok {
            content_type: "text/plain",
            body: format!("{} {}", request.method, request.target),
        }
    }

    async fn exchange(listener: &tokio::net::TcpListener, sent: &[u8]) -> String {
        let address = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(sent).await.unwrap();
        client.shutdown().await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        super::exchange(&mut server, answer).await.unwrap();
        drop(server);
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        String::from_utf8(received).unwrap()
    }

    #[test]
    fn request_line_is_a_method_a_target_and_http_1() {
        for (head, expected) in [
            (
                &b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n"[..],
                Some(("GET", "/metrics")),
            ),
            (b"GET /metrics HTTP/1.0\r\n\r\n", Some(("GET", "/metrics"))),
            (b"POST /a?b=c HTTP/1.1\r\n\r\n", Some(("POST", "/a?b=c"))),
            (b"M-1 * HTTP/1.1\r\n\r\n", Some(("M-1", "*"))),
            (b"GET /metrics HTTP/2\r\n\r\n", None),
            (b"GET /metrics http/1.1\r\n\r\n", None),
            (b"GET /metrics\r\n\r\n", None),
            (b"GET  /metrics HTTP/1.1\r\n\r\n", None),
            (b"GET /metrics HTTP/1.1 \r\n\r\n", None),
            (b" GET /metrics HTTP/1.1\r\n\r\n", None),
            (b"G(T /metrics HTTP/1.1\r\n\r\n", None),
            (b"GET /m\x7fetrics HTTP/1.1\r\n\r\n", None),
            (b"GET /\xc3\xa9 HTTP/1.1\r\n\r\n", None),
            (b"GET /\xff HTTP/1.1\r\n\r\n", None),
            (b"\r\n\r\n", None),
        ] {
            let request =
                super::request(head).map(|super::Request { method, target }| (method, target));
            assert_eq!(request, expected, "{:?}", String::from_utf8_lossy(head));
        }
    }

    #[test]
    fn each_response_has_its_status_its_headers_and_a_length() {
        for (response, expected) in [
            (
                super::Response::Ok {
                    content_type: "text/plain",
                    body: String::from("ab"),
                },
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\
                 Connection: close\r\n\r\nab",
            ),
            (
                super::Response::BadRequest,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            (
                super::Response::NotFound,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            (
                super::Response::MethodNotAllowed { allow: "GET" },
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n",
            ),
        ] {
            assert_eq!(String::from_utf8(response.bytes()).unwrap(), expected);
        }
    }

    #[test]
    fn header_value_with_a_line_end_is_a_bug() {
        for value in ["a\rb", "a\nb", "a\r\nB: c"] {
            for response in [
                super::Response::Ok {
                    content_type: value,
                    body: String::new(),
                },
                super::Response::MethodNotAllowed { allow: value },
            ] {
                let written = std::panic::catch_unwind(|| response.bytes());
                assert!(written.is_err(), "{value:?}");
            }
        }
    }

    #[test]
    fn exchange_answers_a_head_and_refuses_a_bad_or_long_one() {
        let fits = format!(
            "GET / HTTP/1.1\r\nA: {}\r\n\r\n",
            "a".repeat(super::HEAD_LENGTH_MAX - 23)
        );
        assert_eq!(fits.len(), 8 * 1024);
        let long = format!(
            "GET / HTTP/1.1\r\nA: {}\r\n\r\n",
            "a".repeat(super::HEAD_LENGTH_MAX - 22)
        );
        let ok = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        block_on(async {
            let listener = super::listen("127.0.0.1:0".parse().unwrap()).unwrap();
            for (sent, expected) in [
                (&b"GET /metrics HTTP/1.1\r\n\r\n"[..], ok("GET /metrics")),
                (b"GET /metrics HTTP/1.1\r\n\r\nbody", ok("GET /metrics")),
                (fits.as_bytes(), ok("GET /")),
                (long.as_bytes(), String::from(bad)),
                (b"GET /metrics\r\n\r\n", String::from(bad)),
                (b"GET /metrics HTTP/1.1\r\n", String::new()),
                (b"", String::new()),
            ] {
                let received = exchange(&listener, sent).await;
                assert_eq!(received, expected, "{:?}", String::from_utf8_lossy(sent));
            }
        });
    }

    #[test]
    fn head_end_over_two_reads_is_found() {
        let head = b"GET / HTTP/1.1\r\n\r\n";
        block_on(async {
            for split in 1..super::HEAD_END.len() {
                let (first, second) = head.split_at(head.len() - split);
                let mut reader = AsyncReadExt::chain(first, second);
                let read = super::read_head(&mut reader).await.unwrap();
                assert_eq!(read, head, "{split}");
            }
        });
    }
}
