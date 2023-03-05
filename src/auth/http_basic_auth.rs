use base64::Engine;
use rocket::{request, Request};
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;

#[derive(Debug)]
pub struct HttpBasicAuth {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug)]
pub enum HttpBasicAuthError {
    BadCount,
    Missing,
    Invalid,
}

impl HttpBasicAuth {
    pub fn from_header<T: Into<String>>(auth_header: T) -> Option<Self> {
        let key = auth_header.into();

        if key.len() < 7 || &key[..6] != "Basic " {
            return None;
        }

        decode(&key[6..])
            .map(|(client_id, client_secret)| Self { client_id, client_secret })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for HttpBasicAuth {
    type Error = HttpBasicAuthError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<HttpBasicAuth, Self::Error> {
        let values: Vec<_> = request.headers().get("Authorization").collect();
        match values.len() {
            0 => {
                warn!("Authorization header: None");
                Outcome::Failure((Status::BadRequest, HttpBasicAuthError::Missing))
            }
            1 => match HttpBasicAuth::from_header(values[0]) {
                Some(auth) => Outcome::Success(auth),
                None => {
                    warn!("Authorization header: invalid");
                    Outcome::Failure((Status::BadRequest, HttpBasicAuthError::Invalid))
                }
            }
            _ => {
                warn!("Authorization header: too many");
                Outcome::Failure((Status::BadRequest, HttpBasicAuthError::BadCount))
            }
        }
    }
}

fn decode<T: Into<String>>(encoded: T) -> Option<(String, String)> {
    let engine = base64::engine::general_purpose::STANDARD;
    let res_decoded = engine.decode(encoded.into())
        .map(|bytes| String::from_utf8(bytes).unwrap());
    match res_decoded {
        Ok(decoded) => split_credential(decoded),
        Err(e) => {
            warn!("can not decode from base64: {:?}", e);
            None
        }
    }
}

#[inline]
fn split_credential(decoded: String) -> Option<(String, String)> {
    if let Some((c_id, c_secret)) = decoded.split_once(":") {
        Some((c_id.to_string(), c_secret.to_string()))
    } else {
        warn!("decoded header format is wrong");
        None
    }
}