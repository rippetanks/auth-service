use std::fs::File;
use std::io::{BufReader, Error, Read};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use josekit::jwe::{A256GCMKW, JweHeader};
use josekit::jwt::{encode_with_encrypter, JwtPayload};
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::config::Config;
use crate::controller::AuthToken;
use crate::oauth::model::{OAuthCode, OAuthCredential};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AccessToken {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub jti: String,
}

#[derive(Debug)]
pub struct RefreshToken {
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

pub fn read_jwt(header: &str, secret: &String) -> Result<AuthToken, String> {
    let headers = header.split("Bearer ").collect::<Vec<&str>>();
    if headers.len() != 2 || headers[1].len() == 0 {
        warn!("Invalid JWT token: {}", header);
        return Err(String::from("Token not valid!"));
    }
    let decode_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS512);
    match decode::<AuthToken>(headers[1], &decode_key, &validation) {
        Ok(t) => Ok(t.claims),
        Err(e) => {
            warn!("Invalid JWT token: {}", e);
            Err(String::from("Token not valid!"))
        }
    }
}

/// Create an access token (JWT) for OAuth2 authorization code or client credentials flow
pub fn create_oauth2_access_token(auth_info: &AuthInfo,
                                  config: &Config) -> Result<(String, AccessToken), Status> {
    let header = Header::new(Algorithm::ES384);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = AccessToken {
        sub: auth_info.user_id.to_string(),
        exp: now + config.oauth_access_token_exp,
        iat: now,
        iss: config.oauth_jwt_issuer.to_string(),
        jti: Uuid::new_v4().to_string(),
    };
    let sign_key = get_sign_key(config).unwrap();
    let encoding_key = get_encoding_key(&sign_key).map_err(|e| {
        error!("can not create encoding key for JWT access token - cause: {}", e);
        Status::InternalServerError
    })?;
    let token = encode(&header, &claims, &encoding_key).map_err(|e| {
        error!("can not encode JWT access token - cause: {}", e);
        Status::InternalServerError
    })?;
    debug!("encoded token: {}", token);
    Ok((token, claims))
}

pub fn read_oauth2_refresh_token(token: &str, secret: &str) -> Result<RefreshToken, Status> {
    let dec = A256GCMKW.decrypter_from_bytes(secret.as_bytes()).map_err(|e| {
        error!("can not create JWE decrypter - cause: {}", e);
        Status::InternalServerError
    })?;
    let (payload, header) = josekit::jwt::decode_with_decrypter(token, &dec).map_err(|e| {
        warn!("can not decrypt JWE - cause: {}", e);
        Status::Unauthorized
    })?;
    debug!("refresh token payload: {}", payload);
    debug!("refresh token header: {}", header);
    Ok(RefreshToken {
        sub: payload.subject().unwrap().to_string(),
        exp: payload.expires_at().unwrap(),
        iat: payload.issued_at().unwrap(),
        iss: payload.issuer().unwrap().to_string(),
        jti: payload.jwt_id().unwrap().to_string(),
        client_id: payload.claim("client_id").unwrap().as_str().unwrap().to_string(),
        correlation_id: payload.claim("correlation_id").unwrap().as_str().unwrap().to_string(),
        user_id: payload.claim("user_id").unwrap().as_i64().unwrap(),
        app_id: payload.claim("app_id").unwrap().as_i64().unwrap(),
    })
}

/// Create a refresh token (JWE) for OAuth2 authorization code flow
pub fn create_oauth2_refresh_token(code: Option<&OAuthCode>,
                                   previous: Option<&RefreshToken>,
                                   config: &Config) -> Result<(String, RefreshToken), Status> {
    if code.is_none() && previous.is_none() {
        error!("should specified at lest one between OAuthCode or OAuthRefresh");
        return Err(Status::InternalServerError);
    }
    let sub = code.map_or_else(|| previous.unwrap().user_id, |c| c.user_id).to_string();
    let iat = SystemTime::now();
    let exp = iat.add(Duration::from_secs(config.oauth_refresh_token_inactivity_exp));
    let jti = Uuid::new_v4().to_string();
    let client_id = code.map_or_else(|| previous.unwrap().client_id.clone(), |c| c.client_id.clone());
    let correlation_id = previous.map_or_else(|| Uuid::new_v4().to_string(), |p| p.correlation_id.clone());
    let user_id = code.map_or_else(|| previous.unwrap().user_id, |c| c.user_id);
    let app_id = code.map_or_else(|| previous.unwrap().app_id, |c| c.app_id);

    let info = RefreshToken {
        sub,
        exp,
        iat,
        iss: config.oauth_jwt_issuer.clone(),
        jti,
        client_id,
        correlation_id,
        user_id,
        app_id,
    };

    let header = create_oauth2_refresh_token_header();
    let payload = create_oauth2_refresh_token_payload(&info);

    let enc = A256GCMKW.encrypter_from_bytes(config.oauth_jwt_encrypt_key.as_bytes()).map_err(|e| {
        error!("can not create JWE encrypter - cause: {}", e);
        Status::InternalServerError
    })?;
    let token = encode_with_encrypter(&payload, &header, &enc).map_err(|e| {
        error!("can not encrypt JWE token - cause: {}", e);
        Status::InternalServerError
    })?;
    Ok((token, info))
}

fn create_oauth2_refresh_token_header() -> JweHeader {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A256GCM");
    header
}

fn create_oauth2_refresh_token_payload(info: &RefreshToken) -> JwtPayload {
    let mut payload = JwtPayload::new();
    payload.set_subject(&info.sub);
    payload.set_expires_at(&info.exp);
    payload.set_issued_at(&info.iat);
    payload.set_issuer(&info.iss);
    payload.set_jwt_id(&info.jti);
    payload.set_claim("client_id", Some(info.client_id.clone().into()))
        .expect("Invalid JWT claim!");
    payload.set_claim("correlation_id", Some(info.correlation_id.clone().into()))
        .expect("Invalid JWT claim!");
    payload.set_claim("user_id", Some(info.user_id.into()))
        .expect("Invalid JWT claim!");
    payload.set_claim("app_id", Some(info.app_id.into()))
        .expect("Invalid JWT claim!");
    payload
}

fn get_encoding_key(sign_key: &Vec<u8>) -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    match EncodingKey::from_ec_pem(sign_key) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not create encoding key - cause {}", e);
            Err(e)
        }
    }
}

fn get_sign_key(config: &Config) -> Result<Vec<u8>, Error> {
    match read_sign_key(config) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not get sign key - cause {}", e);
            Err(e)
        }
    }
}

fn read_sign_key(config: &Config) -> Result<Vec<u8>, Error> {
    let file = File::open(&config.oauth_jwt_sign_key_path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
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

impl From<RefreshToken> for AuthInfo {
    fn from(token: RefreshToken) -> Self {
        Self {
            user_id: token.user_id,
        }
    }
}

impl From<&RefreshToken> for AuthInfo {
    fn from(token: &RefreshToken) -> Self {
        Self {
            user_id: token.user_id,
        }
    }
}