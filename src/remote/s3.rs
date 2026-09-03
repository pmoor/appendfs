use crate::remote::sigv4::SigV4Signer;
use crate::remote::{RemoteObject, RemoteStore};
use quick_xml::events::Event;
use quick_xml::reader::Reader as XmlReader;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::time::Duration;
use url::Url;

/// S3-compatible remote storage client using standard S3 REST operations.
#[derive(Debug, Clone)]
pub struct S3RemoteStore {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub prefix: String,
    pub signer: Option<SigV4Signer>,
    pub force_path_style: bool,
    agent: ureq::Agent,
}

impl S3RemoteStore {
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        endpoint: Option<String>,
        prefix: impl Into<String>,
        signer: Option<SigV4Signer>,
        force_path_style: bool,
    ) -> Self {
        let agent = ureq::builder()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(60))
            .timeout_write(Duration::from_secs(60))
            .build();

        let mut p = prefix.into();
        if !p.is_empty() && !p.ends_with('/') {
            p.push('/');
        }

        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint,
            prefix: p,
            signer,
            force_path_style,
            agent,
        }
    }

    fn full_key(&self, key: &str) -> String {
        let trimmed = key.trim_start_matches('/');
        format!("{}{}", self.prefix, trimmed)
    }

    fn resolve_endpoint(&self) -> (String, String, String) {
        // Returns (base_url, host_header, canonical_base_path)
        if let Some(ref ep) = self.endpoint {
            let parsed = Url::parse(ep).unwrap_or_else(|_| Url::parse("http://127.0.0.1:9000").unwrap());
            let host_header = match parsed.port() {
                Some(port) => format!("{}:{}", parsed.host_str().unwrap_or(""), port),
                None => parsed.host_str().unwrap_or("").to_string(),
            };

            let base = ep.trim_end_matches('/');
            if self.force_path_style {
                (
                    format!("{}/{}", base, self.bucket),
                    host_header,
                    format!("/{}", self.bucket),
                )
            } else {
                (base.to_string(), host_header, "".to_string())
            }
        } else if self.force_path_style {
            let host = format!("s3.{}.amazonaws.com", self.region);
            (
                format!("https://{}/{}", host, self.bucket),
                host,
                format!("/{}", self.bucket),
            )
        } else {
            let host = format!("{}.s3.{}.amazonaws.com", self.bucket, self.region);
            (format!("https://{}", host), host, "".to_string())
        }
    }

    fn format_now_datetime() -> String {
        let now = std::time::SystemTime::now();
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let secs = dur.as_secs();

        // Standard UTC breakdown
        let days = secs / 86400;
        let rem_secs = secs % 86400;
        let hours = rem_secs / 3600;
        let minutes = (rem_secs % 3600) / 60;
        let seconds = rem_secs % 60;

        let (year, month, day) = days_to_date(days);
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }

    fn sign_and_build_req(
        &self,
        method: &str,
        raw_key: &str,
        query: &[(String, String)],
        extra_headers: &[(String, String)],
        payload_sha256: &str,
    ) -> io::Result<ureq::Request> {
        let (base_url, host_header, canonical_base_path) = self.resolve_endpoint();
        let key_path = if raw_key.is_empty() {
            "".to_string()
        } else {
            format!("/{}", raw_key.trim_start_matches('/'))
        };

        let target_url = format!("{}{}", base_url, key_path);
        let canonical_path = format!("{}{}", canonical_base_path, key_path);

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), host_header);
        for (k, v) in extra_headers {
            headers.insert(k.to_ascii_lowercase(), v.clone());
        }

        let mut req = match method {
            "GET" => self.agent.get(&target_url),
            "PUT" => self.agent.put(&target_url),
            "HEAD" => self.agent.head(&target_url),
            "DELETE" => self.agent.delete(&target_url),
            _ => return Err(io::Error::new(io::ErrorKind::Unsupported, method)),
        };

        for (k, v) in query {
            req = req.query(k, v);
        }

        if let Some(ref signer) = self.signer {
            let datetime = Self::format_now_datetime();
            let (auth, date, sha) =
                signer.sign_request(method, &canonical_path, query, &headers, payload_sha256, &datetime);
            req = req
                .set("Authorization", &auth)
                .set("x-amz-date", &date)
                .set("x-amz-content-sha256", &sha);
        }

        for (k, v) in extra_headers {
            req = req.set(k, v);
        }

        Ok(req)
    }

    fn parse_error_response(resp: ureq::Response) -> io::Error {
        let status = resp.status();
        let mut reader = resp.into_reader();
        let mut body = String::new();
        let _ = reader.read_to_string(&mut body);

        // Try extracting <Code> and <Message> from S3 error XML
        let mut code = String::new();
        let mut message = String::new();
        let mut in_code = false;
        let mut in_message = false;

        let mut xml = XmlReader::from_str(&body);
        let mut buf = Vec::new();
        while let Ok(event) = xml.read_event_into(&mut buf) {
            match event {
                Event::Start(e) if e.name().as_ref() == b"Code" => in_code = true,
                Event::End(e) if e.name().as_ref() == b"Code" => in_code = false,
                Event::Start(e) if e.name().as_ref() == b"Message" => in_message = true,
                Event::End(e) if e.name().as_ref() == b"Message" => in_message = false,
                Event::Text(t) => {
                    if in_code {
                        code = t.unescape().unwrap_or_default().to_string();
                    } else if in_message {
                        message = t.unescape().unwrap_or_default().to_string();
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        let kind = match status {
            404 => io::ErrorKind::NotFound,
            400 if code == "BadDigest" => io::ErrorKind::InvalidData,
            401 | 403 => io::ErrorKind::PermissionDenied,
            429 | 503 => io::ErrorKind::WouldBlock,
            _ => io::ErrorKind::Other,
        };

        if !code.is_empty() || !message.is_empty() {
            io::Error::new(kind, format!("S3 error HTTP {} [{}]: {}", status, code, message))
        } else {
            io::Error::new(kind, format!("S3 error HTTP {}: {}", status, body.trim()))
        }
    }
}

impl RemoteStore for S3RemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        let full_prefix = format!("{}{}", self.prefix, prefix.trim_start_matches('/'));
        let mut continuation_token: Option<String> = None;
        let mut results = Vec::new();

        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), full_prefix.clone()),
            ];
            if let Some(ref token) = continuation_token {
                query.push(("continuation-token".to_string(), token.clone()));
            }

            let req = self.sign_and_build_req(
                "GET",
                "",
                &query,
                &[],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )?;

            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(_, resp)) => return Err(Self::parse_error_response(resp)),
                Err(e) => return Err(io::Error::other(e)),
            };

            let mut reader = resp.into_reader();
            let mut xml_str = String::new();
            reader.read_to_string(&mut xml_str)?;

            let mut xml = XmlReader::from_str(&xml_str);
            let mut buf = Vec::new();

            let mut in_contents = false;
            let mut in_key = false;
            let mut in_size = false;
            let mut in_etag = false;
            let mut in_is_trunc = false;
            let mut in_next_token = false;

            let mut cur_key = String::new();
            let mut cur_size = 0u64;
            let mut cur_etag = String::new();
            let mut is_truncated = false;
            let mut next_token = String::new();

            while let Ok(event) = xml.read_event_into(&mut buf) {
                match event {
                    Event::Start(e) => match e.name().as_ref() {
                        b"Contents" => {
                            in_contents = true;
                            cur_key.clear();
                            cur_size = 0;
                            cur_etag.clear();
                        }
                        b"Key" if in_contents => in_key = true,
                        b"Size" if in_contents => in_size = true,
                        b"ETag" if in_contents => in_etag = true,
                        b"IsTruncated" => in_is_trunc = true,
                        b"NextContinuationToken" => in_next_token = true,
                        _ => {}
                    },
                    Event::End(e) => match e.name().as_ref() {
                        b"Contents" => {
                            in_contents = false;
                            // Strip global prefix to make key relative to prefix root
                            let rel_key = cur_key.strip_prefix(&self.prefix).unwrap_or(&cur_key).to_string();
                            results.push(RemoteObject {
                                key: rel_key,
                                size: cur_size,
                                etag: Some(cur_etag.trim_matches('"').to_string()),
                                last_modified: None,
                            });
                        }
                        b"Key" => in_key = false,
                        b"Size" => in_size = false,
                        b"ETag" => in_etag = false,
                        b"IsTruncated" => in_is_trunc = false,
                        b"NextContinuationToken" => in_next_token = false,
                        _ => {}
                    },
                    Event::Text(t) => {
                        let text = t.unescape().unwrap_or_default();
                        if in_key {
                            cur_key = text.to_string();
                        } else if in_size {
                            cur_size = text.parse().unwrap_or(0);
                        } else if in_etag {
                            cur_etag = text.to_string();
                        } else if in_is_trunc {
                            is_truncated = text.eq_ignore_ascii_case("true");
                        } else if in_next_token {
                            next_token = text.to_string();
                        }
                    }
                    Event::Eof => break,
                    _ => {}
                }
                buf.clear();
            }

            if is_truncated && !next_token.is_empty() {
                continuation_token = Some(next_token);
            } else {
                break;
            }
        }

        Ok(results)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        let full_key = self.full_key(key);
        let req = self.sign_and_build_req(
            "HEAD",
            &full_key,
            &[],
            &[],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;

        match req.call() {
            Ok(resp) => {
                let size = resp
                    .header("content-length")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                let etag = resp.header("etag").map(|e| e.trim_matches('"').to_string());
                Ok(Some(RemoteObject {
                    key: key.to_string(),
                    size,
                    etag,
                    last_modified: None,
                }))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(_, resp)) => Err(Self::parse_error_response(resp)),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        let full_key = self.full_key(key);
        let mut extra_headers = vec![
            ("Content-Length".to_string(), len.to_string()),
            ("Content-Type".to_string(), "application/octet-stream".to_string()),
        ];
        if let Some(md5_bytes) = content_md5 {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(md5_bytes);
            extra_headers.push(("Content-MD5".to_string(), b64));
        }

        let req = self.sign_and_build_req("PUT", &full_key, &[], &extra_headers, "UNSIGNED-PAYLOAD")?;

        match req.send(reader.take(len)) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(_, resp)) => Err(Self::parse_error_response(resp)),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        let full_key = self.full_key(key);
        let req = self.sign_and_build_req(
            "GET",
            &full_key,
            &[],
            &[],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;

        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, resp)) => return Err(Self::parse_error_response(resp)),
            Err(e) => return Err(io::Error::other(e)),
        };

        let mut body_reader = resp.into_reader();
        io::copy(&mut body_reader, writer)
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        let full_key = self.full_key(key);
        let range_header = format!("bytes={}-{}", offset, offset + len - 1);
        let extra_headers = vec![("Range".to_string(), range_header)];

        let req = self.sign_and_build_req(
            "GET",
            &full_key,
            &[],
            &extra_headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;

        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, resp)) => return Err(Self::parse_error_response(resp)),
            Err(e) => return Err(io::Error::other(e)),
        };

        let mut body_reader = resp.into_reader();
        io::copy(&mut body_reader, writer)
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        let full_key = self.full_key(key);
        let req = self.sign_and_build_req(
            "DELETE",
            &full_key,
            &[],
            &[],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;

        match req.call() {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Ok(()), // S3 delete idempotent
            Err(ureq::Error::Status(_, resp)) => Err(Self::parse_error_response(resp)),
            Err(e) => Err(io::Error::other(e)),
        }
    }
}

fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Gregorian cycle calculation
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
