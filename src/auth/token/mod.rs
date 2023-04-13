use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use rocket::State;
use uuid::Uuid;
use crate::config::Config;
use crate::oauth::model::{OAuthCode, OAuthCredential};
use crate::users::model::User;

pub(super) mod utils;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthToken {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub jti: String,
}

#[derive(Debug)]
pub enum AuthTokenError {
    BadCount,
    Missing,
    Invalid,
    Broken,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthAccessToken {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub jti: String,
}

#[derive(Debug)]
pub struct OAuthRefreshToken {
    pub sub: String,
    pub exp: SystemTime,
    pub iat: SystemTime,
    pub iss: String,
    pub jti: String,
    pub client_id: String,
    pub correlation_id: String,
    pub app_id: i64,
    pub user_id: i64,
}

#[derive(Debug)]
pub struct AuthInfo {
    user_id: i64,
}

const TOKEN_NOT_VALID: &str = "Token not valid!";

/// Parse and verify signature of a JWT signed with HMAC using SHA-512
pub fn read_jwt(token: &str, secret: &String) -> Result<AuthToken, &'static str> {
    let decode_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS512);
    match jsonwebtoken::decode::<AuthToken>(token, &decode_key, &validation) {
        Ok(t) => Ok(t.claims),
        Err(e) => {
            warn!("Invalid JWT token: {}", e);
            Err(TOKEN_NOT_VALID)
        }
    }
}

/// Generate a JWT signed with HMAC using SHA-512
pub fn generate_jwt_token(user: &User, config: &State<Config>) -> Result<String, Status> {
    let header = Header::new(Algorithm::HS512);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = AuthToken {
        sub: user.id,
        exp: (now + config.jwt_exp) as usize,
        iat: now as usize,
        iss: "".to_string(),
        jti: Uuid::new_v4().to_string(),
    };
    let encoding_key = EncodingKey::from_secret(config.jwt_key.as_ref());
    match jsonwebtoken::encode(&header, &claims, &encoding_key) {
        Ok(token) => Ok(token),
        Err(e) => {
            error!("can not encode JWT token - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

impl From<OAuthCredential> for AuthInfo {
    fn from(credential: OAuthCredential) -> Self {
        Self {
            user_id: credential.user_id,
        }
    }
}

impl From<&OAuthCredential> for AuthInfo {
    fn from(credential: &OAuthCredential) -> Self {
        Self {
            user_id: credential.user_id,
        }
    }
}

impl From<OAuthCode> for AuthInfo {
    fn from(code: OAuthCode) -> Self {
        Self {
            user_id: code.user_id,
        }
    }
}

impl From<&OAuthCode> for AuthInfo {
    fn from(code: &OAuthCode) -> Self {
        Self {
            user_id: code.user_id,
        }
    }
}

impl From<OAuthRefreshToken> for AuthInfo {
    fn from(token: OAuthRefreshToken) -> Self {
        Self {
            user_id: token.user_id,
        }
    }
}

impl From<&OAuthRefreshToken> for AuthInfo {
    fn from(token: &OAuthRefreshToken) -> Self {
        Self {
            user_id: token.user_id,
        }
    }
}
