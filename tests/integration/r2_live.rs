//! Live R2 integration tests.
//!
//! These are `#[ignore]`-marked so default `cargo test` skips them.
//! To run, point at a dedicated R2 bucket via env vars:
//!
//! ```sh
//! CAIRN_R2_ENDPOINT=https://<account_id>.r2.cloudflarestorage.com \
//! CAIRN_R2_BUCKET=cairn-tests \
//! CAIRN_R2_ACCESS_KEY_ID=... \
//! CAIRN_R2_SECRET_ACCESS_KEY=... \
//! cargo test -p cairn-integration-tests --test r2_live -- --ignored
//! ```
//!
//! What the tests cover:
//!
//! 1. **Happy path** through `cairn_remote::Remote::r2` (which sets
//!    `with_checksum_algorithm(SHA256)` on `AmazonS3Builder`): chunk
//!    PUT + HEAD + GET round-trip, and manifest PUT + GET. Proves the
//!    SHA-256 header that `object_store` adds is the one R2 expects.
//! 2. **Rejection on bad checksum.** Hand-rolled SigV4 PUT with an
//!    `x-amz-checksum-sha256` header claiming a value that does NOT
//!    match the body's SHA-256. R2 must respond 4xx. Without the
//!    `with_checksum_algorithm` setting in place server-side, R2
//!    would silently accept the upload; this test is what proves
//!    Cairn's M18 upload-integrity guarantee end-to-end.
//! 3. **Accept on correct checksum.** Same hand-rolled path but with
//!    the right SHA-256 — must return 2xx. Symmetry test.
//!
//! object_store doesn't expose a way to override the SHA-256 it
//! computes from the body, so tests 2 and 3 hand-roll a SigV4 PUT
//! using `aws-sigv4` + `reqwest` — exactly the pattern Cairn would
//! avoid in production (we want object_store's abstractions) but
//! which is necessary here to inject a deliberately wrong checksum.

use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use cairn_remote::Remote;
use cairn_types::{ChunkId, ContentHash};
use sha2::{Digest, Sha256};

const ENDPOINT_VAR: &str = "CAIRN_R2_ENDPOINT";
const BUCKET_VAR: &str = "CAIRN_R2_BUCKET";
const ACCESS_VAR: &str = "CAIRN_R2_ACCESS_KEY_ID";
const SECRET_VAR: &str = "CAIRN_R2_SECRET_ACCESS_KEY";

/// Test harness: env config + a `reqwest::Client` + signed AWS creds,
/// plus a per-process-per-test unique key prefix so concurrent test
/// runs against the same bucket don't collide.
struct R2Test {
    endpoint: String,
    bucket: String,
    access: String,
    secret: String,
    prefix: String,
    http: reqwest::Client,
    creds: Credentials,
}

impl R2Test {
    fn from_env() -> Option<Self> {
        let endpoint = env::var(ENDPOINT_VAR).ok()?;
        let bucket = env::var(BUCKET_VAR).ok()?;
        let access = env::var(ACCESS_VAR).ok()?;
        let secret = env::var(SECRET_VAR).ok()?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("cairn-tests/{}-{}", std::process::id(), nanos);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        let creds = Credentials::new(&access, &secret, None, None, "cairn-r2-tests");
        Some(Self {
            endpoint,
            bucket,
            access,
            secret,
            prefix,
            http,
            creds,
        })
    }

    fn skip_if_no_env() -> Option<Self> {
        match Self::from_env() {
            Some(t) => Some(t),
            None => {
                eprintln!(
                    "skipping live R2 test: set {ENDPOINT_VAR}, {BUCKET_VAR}, {ACCESS_VAR}, {SECRET_VAR}"
                );
                None
            }
        }
    }

    fn object_url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.bucket,
            key
        )
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Sign and send a raw HTTP request via SigV4. `extra_headers` are
/// included in the canonical signing set, so adding
/// `x-amz-checksum-sha256` here actually requires R2 to validate it.
async fn signed_request(
    t: &R2Test,
    method: &str,
    url: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    let host = reqwest::Url::parse(url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let body_sha256 = hex::encode(Sha256::digest(body));
    let content_length = body.len().to_string();

    let mut headers: Vec<(&str, &str)> = vec![
        ("host", host.as_str()),
        ("content-length", content_length.as_str()),
        ("x-amz-content-sha256", &body_sha256),
    ];
    for (k, v) in extra_headers {
        headers.push((*k, *v));
    }

    let settings = SigningSettings::default();
    let identity = t.creds.clone().into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("auto")
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let signable = SignableRequest::new(
        method,
        url,
        headers.iter().map(|(n, v)| (*n, *v)),
        SignableBody::Precomputed(body_sha256.clone()),
    )
    .unwrap();
    let (instructions, _sig) = sign(signable, &params).unwrap().into_parts();

    let mut req = http::Request::builder()
        .method(method)
        .uri(url)
        .body(Vec::<u8>::new())
        .unwrap();
    for (k, v) in &headers {
        let name = http::HeaderName::from_bytes(k.as_bytes()).unwrap();
        req.headers_mut()
            .insert(name, http::HeaderValue::from_str(v).unwrap());
    }
    instructions.apply_to_request_http1x(&mut req);

    let mut rq = reqwest::Request::new(
        req.method().clone(),
        req.uri().to_string().parse().unwrap(),
    );
    *rq.headers_mut() = req.headers().clone();
    *rq.body_mut() = Some(reqwest::Body::from(body.to_vec()));

    let resp = t.http.execute(rq).await.expect("HTTP send failed");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

async fn raw_put(
    t: &R2Test,
    key: &str,
    body: &[u8],
    checksum_b64: Option<&str>,
) -> (u16, String) {
    let url = t.object_url(key);
    let extra: Vec<(&str, &str)> = match checksum_b64 {
        Some(c) => vec![("x-amz-checksum-sha256", c)],
        None => vec![],
    };
    signed_request(t, "PUT", &url, body, &extra).await
}

async fn raw_delete(t: &R2Test, key: &str) -> u16 {
    let url = t.object_url(key);
    let (status, _) = signed_request(t, "DELETE", &url, b"", &[]).await;
    status
}

#[test]
#[ignore]
fn r2_chunk_roundtrip_via_cairn_remote() {
    let Some(t) = R2Test::skip_if_no_env() else {
        return;
    };
    rt().block_on(async {
        let remote =
            Remote::r2(&t.endpoint, &t.bucket, &t.access, &t.secret).expect("build Remote");
        let payload = format!("hello cairn r2 chunk roundtrip {}", t.prefix).into_bytes();
        let id = ChunkId::from_data(&payload);

        // PUT — object_store adds the x-amz-checksum-sha256 it computed
        // from `payload`. If R2 didn't actually accept that header, this
        // would 400 right here.
        remote
            .put_chunk_if_absent(id, Bytes::from(payload.clone()))
            .await
            .expect("put_chunk_if_absent must succeed against R2");

        assert!(
            remote.has_chunk(id).await.expect("has_chunk"),
            "chunk must be present after put"
        );
        let got = remote.get_chunk(id).await.expect("get_chunk");
        assert_eq!(got, payload, "round-tripped bytes must match");

        // Cleanup.
        remote.delete_chunk(id).await.expect("delete_chunk");
        assert!(
            !remote.has_chunk(id).await.expect("has_chunk after delete"),
            "chunk must be gone after delete"
        );
    });
}

#[test]
#[ignore]
fn r2_manifest_roundtrip_via_cairn_remote() {
    let Some(t) = R2Test::skip_if_no_env() else {
        return;
    };
    rt().block_on(async {
        let remote =
            Remote::r2(&t.endpoint, &t.bucket, &t.access, &t.secret).expect("build Remote");
        let content =
            ContentHash::from_data(format!("manifest test {}", t.prefix).as_bytes());
        let manifest_bytes = Bytes::from_static(b"postcard-manifest-blob");
        remote
            .put_manifest_if_absent(content, manifest_bytes.clone())
            .await
            .expect("put_manifest_if_absent");
        let got = remote.get_manifest(content).await.expect("get_manifest");
        assert_eq!(got, manifest_bytes);
        remote.delete_manifest(content).await.expect("delete_manifest");
    });
}

#[test]
#[ignore]
fn r2_rejects_put_with_wrong_x_amz_checksum_sha256() {
    let Some(t) = R2Test::skip_if_no_env() else {
        return;
    };
    rt().block_on(async {
        let key = format!("{}/wrong-checksum", t.prefix);
        let payload = b"actual payload bytes whose sha256 will NOT match the claimed value";
        // Wrong SHA-256 (all 0xAA, 32 bytes) — base64-encoded as R2
        // expects. The body's real SHA-256 is something else entirely;
        // R2 must reject when it recomputes and compares.
        let wrong = BASE64.encode([0xAAu8; 32]);
        let (status, body) = raw_put(&t, &key, payload, Some(&wrong)).await;
        assert!(
            (400..500).contains(&status),
            "expected 4xx rejection from R2 for mismatched x-amz-checksum-sha256, \
             got {status}: {body}"
        );
        // R2 returns "BadDigest" or "InvalidDigest" in the error body
        // depending on the exact mode; we don't pin the exact phrase but
        // the status class is the contract.
        eprintln!("R2 rejection body (informational): {body}");
    });
}

#[test]
#[ignore]
fn r2_accepts_put_with_correct_x_amz_checksum_sha256() {
    let Some(t) = R2Test::skip_if_no_env() else {
        return;
    };
    rt().block_on(async {
        let key = format!("{}/correct-checksum", t.prefix);
        let payload = b"matching payload bytes - checksum will be the body's SHA-256";
        let correct = BASE64.encode(Sha256::digest(payload));
        let (status, body) = raw_put(&t, &key, payload, Some(&correct)).await;
        assert!(
            (200..300).contains(&status),
            "expected 2xx accept with correct x-amz-checksum-sha256, got {status}: {body}"
        );
        let _ = raw_delete(&t, &key).await;
    });
}
