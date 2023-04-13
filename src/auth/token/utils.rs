use std::fs::File;
use std::io::{BufReader, Error, Read};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use josekit::jwe::{A256GCMKW, JweHeader};
use josekit::jwt::{encode_with_encrypter, JwtPayload};
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::http::Status;
use uuid::Uuid;
use crate::auth::token::{AuthInfo, OAuthAccessToken, OAuthRefreshToken};
use crate::config::Config;
use crate::oauth::model::OAuthCode;

macro_rules! unauthorized_if_missing {
    ($expr:expr) => {
        $expr.ok_or_else(|| {
            warn!("missing required field in JWT token");
            Status::Unauthorized
        })
    };
}

/// Create an access token (JWT) for OAuth2 authorization code or client credentials flow
pub(in crate::auth) fn create_oauth2_access_token(auth_info: &AuthInfo,
                                                  config: &Config) -> Result<(String, OAuthAccessToken), Status> {
    trace!("creating oauth2 access token {:?} {:?}", auth_info, config);
    let header = Header::new(Algorithm::ES384);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = OAuthAccessToken {
        sub: auth_info.user_id.to_string(),
        exp: now + config.oauth_access_token_exp,
        iat: now,
        iss: config.oauth_jwt_issuer.to_string(),
        jti: Uuid::new_v4().to_string(),
    };
    let sign_key = get_sign_key(config).unwrap();
    let encoding_key = get_encoding_key(&sign_key).map_err(|e| {
        error!("can not create encoding key for OAuth2 JWT access token - cause: {}", e);
        Status::InternalServerError
    })?;
    let token = encode(&header, &claims, &encoding_key).map_err(|e| {
        error!("can not encode OAuth2 JWT access token - cause: {}", e);
        Status::InternalServerError
    })?;
    debug!("encoded token: {}", token);
    Ok((token, claims))
}

/// Parse and verify signature of a JWE OAuth2 refresh token encrypted with AES-256 GCM KW
pub(in crate::auth) fn read_oauth2_refresh_token(token: &str,
                                                 secret: &str) -> Result<OAuthRefreshToken, Status> {
    trace!("reading oauth2 refresh token {} {}", token, secret);
    let dec = A256GCMKW.decrypter_from_bytes(secret.as_bytes()).map_err(|e| {
        error!("can not create JWE decrypter - cause: {}", e);
        Status::InternalServerError
    })?;
    let (payload, header) = josekit::jwt::decode_with_decrypter(token, &dec).map_err(|e| {
        warn!("can not decrypt OAuth2 JWE refresh token - cause: {}", e);
        Status::Unauthorized
    })?;
    debug!("OAuth2 refresh token - header: {} - payload: {}", header, payload);
    Ok(OAuthRefreshToken {
        sub: unauthorized_if_missing!(payload.subject())?.to_string(),
        exp: unauthorized_if_missing!(payload.expires_at())?,
        iat: unauthorized_if_missing!(payload.issued_at())?,
        iss: unauthorized_if_missing!(payload.issuer())?.to_string(),
        jti: unauthorized_if_missing!(payload.jwt_id())?.to_string(),
        client_id: unauthorized_if_missing!(payload.claim("client_id"))?.as_str()
            .expect("client_id must be a string").to_string(),
        correlation_id: unauthorized_if_missing!(payload.claim("correlation_id"))?.as_str()
            .expect("correlation_id must be a string").to_string(),
        user_id: unauthorized_if_missing!(payload.claim("user_id"))?.as_i64()
            .expect("user_id must be an integer"),
        app_id: unauthorized_if_missing!(payload.claim("app_id"))?.as_i64()
            .expect("app_id must be an integer"),
    })
}

/// Create a refresh token (JWE) for OAuth2 authorization code flow
pub(in crate::auth) fn create_oauth2_refresh_token(code: Option<&OAuthCode>,
                                                   previous: Option<&OAuthRefreshToken>,
                                                   config: &Config) -> Result<(String, OAuthRefreshToken), Status> {
    trace!("creating oauth2 refresh token {:?} {:?} {:?}", code, previous, config);
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

    let info = OAuthRefreshToken {
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
        error!("can not encrypt OAuth2 JWE refresh token - cause: {}", e);
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

fn create_oauth2_refresh_token_payload(info: &OAuthRefreshToken) -> JwtPayload {
    let mut payload = JwtPayload::new();
    payload.set_subject(&info.sub);
    payload.set_expires_at(&info.exp);
    payload.set_issued_at(&info.iat);
    payload.set_issuer(&info.iss);
    payload.set_jwt_id(&info.jti);
    payload.set_claim("client_id", Some(info.client_id.clone().into()))
        .expect("Invalid JWT claim: client_id");
    payload.set_claim("correlation_id", Some(info.correlation_id.clone().into()))
        .expect("Invalid JWT claim: correlation_id");
    payload.set_claim("user_id", Some(info.user_id.into()))
        .expect("Invalid JWT claim: user_id");
    payload.set_claim("app_id", Some(info.app_id.into()))
        .expect("Invalid JWT claim: app_id");
    payload
}

// one day all keys will be managed by a Key Management Service and this code must be removed
fn get_encoding_key(sign_key: &Vec<u8>) -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    match EncodingKey::from_ec_pem(sign_key) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not create encoding key - cause: {}", e);
            Err(e)
        }
    }
}

// one day all keys will be managed by a Key Management Service and this code must be removed
fn get_sign_key(config: &Config) -> Result<Vec<u8>, Error> {
    match read_sign_key(config) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not get sign key - cause: {}", e);
            Err(e)
        }
    }
}

// one day all keys will be managed by a Key Management Service and this code must be removed
fn read_sign_key(config: &Config) -> Result<Vec<u8>, Error> {
    let file = File::open(&config.oauth_jwt_sign_key_path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}
