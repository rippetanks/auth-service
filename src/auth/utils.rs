use std::fs::File;
use std::io::{BufReader, Error, Read};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::Utc;
use josekit::jwe::{A256GCMKW, JweHeader};
use josekit::jwt::{encode_with_encrypter, JwtPayload};
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::http::Status;
use rocket::State;
use rocket_db_pools::Connection;
use url::Url;
use uuid::Uuid;
use crate::config::Config;
use crate::controller::AuthToken;
use crate::database::{AuthDB, OAuthCodeDB, OAuthRefreshDB};
use crate::oauth::model::{OAuthApp, OAuthCode, OAuthCredential, OAuthCredentialStatus, OAuthRefresh};
use crate::users::model::User;

#[derive(Debug)]
pub struct RefreshTokenInfo {
    pub token: String,
    pub token_id: String,
    pub correlation_id: String,
}

/// Create an access token (JWT) for OAuth2 client credentials flow
pub fn create_oauth2_cc_token(credential: &OAuthCredential, config: &Config) -> Result<String, Status> {
    create_oauth2_access_token(credential.user_id, config)
}

/// Create an access token (JWT) for OAuth2 authorization code flow
pub fn create_oauth2_ac_token(code: &OAuthCode, config: &Config) -> Result<String, Status> {
    create_oauth2_access_token(code.user_id, config)
}

/// Create a refresh token (JWE) for OAuth2 authorization code flow
pub fn create_auth2_ac_refresh(code: &OAuthCode, config: &Config) -> Result<RefreshTokenInfo, Status> {
    create_oauth2_refresh_token(code.user_id, None, config)
}

pub async fn get_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<OAuthCredential, Status> {
    match try_get_by_client_id(conn, client_id).await? {
        Some(credential) if credential.status != OAuthCredentialStatus::ACTIVE => {
            warn!("Access denied! oauth credential {} is not active", credential.id);
            Err(Status::Unauthorized)
        },
        Some(credential) if credential.expire_at.is_some() && Utc::now() >= credential.expire_at.unwrap() => {
            warn!("Access denied! oauth credential {} is expired", credential.id);
            Err(Status::Unauthorized)
        },
        Some(credential) => Ok(credential),
        None => {
            warn!("oauth credential not found with client_id {}", client_id);
            Err(Status::NotFound)
        }
    }
}

pub async fn get_app_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<OAuthApp, Status> {
    match try_get_app_by_client_id(conn, client_id).await? {
        Some(app) => Ok(app),
        None => {
            warn!("oauth app not found with client_id {}", client_id);
            Err(Status::NotFound)
        }
    }
}

pub async fn get_user_by_email(conn: &mut Connection<AuthDB>, email: &str) -> Result<User, Status> {
    match try_get_by_email(conn, email).await? {
        Some(user) => Ok(user),
        None => {
            warn!("user with email {} not found", email);
            Err(Status::NotFound)
        }
    }
}

pub fn parse_uri(uri: &str) -> Result<Url, Status> {
    Url::parse(uri).map_err(|e| {
        warn!("redirect_uri {} is not formatted correctly - cause {}", uri, e);
        Status::BadRequest
    })
}

pub async fn put_code_to_redis(conn: &mut Connection<OAuthCodeDB>, code: &String, payload: &OAuthCode,
                               config: &State<Config>) -> Result<(), Status> {
    match OAuthCode::insert(code, payload, config.oauth_auth_code_exp, conn).await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("can not add code to Redis - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn get_code_from_redis(conn: &mut Connection<OAuthCodeDB>, code: &str) -> Result<OAuthCode, Status> {
    match OAuthCode::get(code, conn).await {
        Ok(code) => Ok(code),
        Err(e) => {
            error!("can not get code from Redis - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn put_refresh_to_redis(conn: &mut Connection<OAuthRefreshDB>, config: &State<Config>,
                                  token_info: &RefreshTokenInfo, payload: &OAuthRefresh) -> Result<(), Status> {
    match OAuthRefresh::insert(&token_info.token_id, payload, config.oauth_refresh_token_inactivity_exp, conn).await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("can not add refresh token to Redis - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<Option<OAuthCredential>, Status> {
    match OAuthCredential::find_by_client_id(client_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get oauth credential by client_id {} - cause {}", client_id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_app_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<Option<OAuthApp>, Status> {
    match OAuthApp::find_by_client_id(client_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get oauth app by client_id {} - cause {}", client_id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_by_email(conn: &mut Connection<AuthDB>, email: &str) -> Result<Option<User>, Status> {
    match User::find_by_email(email, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get user by email {} - cause {}", email, e);
            Err(Status::InternalServerError)
        }
    }
}

fn create_oauth2_access_token(user_id: i64, config: &Config) -> Result<String, Status> {
    let header = Header::new(Algorithm::ES384);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = AuthToken {
        sub: user_id,
        exp: (now + config.oauth_access_token_exp) as usize,
        iat: now as usize,
        iss: config.oauth_jwt_issuer.to_string(),
        jti: Uuid::new_v4().to_string(),
    };
    let sign_key = get_sign_key(config)?;
    let encoding_key = get_encoding_key(&sign_key)?;
    get_token(&header, &claims, &encoding_key)
}

fn create_oauth2_refresh_token(user_id: i64, prev_c_id: Option<String>, config: &Config) -> Result<RefreshTokenInfo, Status> {
    let now = SystemTime::now();
    let expire_at = now.add(Duration::from_secs(config.oauth_refresh_token_inactivity_exp));

    let token_id = Uuid::new_v4().to_string();
    let correlation_id = prev_c_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A256GCM");

    let mut payload = JwtPayload::new();
    payload.set_subject(user_id.to_string());
    payload.set_expires_at(&expire_at);
    payload.set_issued_at(&now);
    payload.set_issuer(&config.oauth_jwt_issuer);
    payload.set_jwt_id(&token_id);
    payload.set_claim("correlation_id", Some(correlation_id.to_string().into()))
        .expect("invalid JWT claim");

    let enc = A256GCMKW.encrypter_from_bytes(config.oauth_jwt_encrypt_key.as_bytes()).map_err(|e| {
       error!("can not create encrypt for JWE - cause {}", e);
        Status::InternalServerError
    })?;
    encode_with_encrypter(&payload, &header, &enc).map_err(|e| {
        error!("can not encrypt JWE - cause {}", e);
        Status::InternalServerError
    }).map(|token| RefreshTokenInfo {
        token,
        token_id,
        correlation_id,
    })
}

fn get_token(header: &Header, claims: &AuthToken, encoding_key: &EncodingKey) -> Result<String, Status> {
    match encode(header, claims, encoding_key) {
        Ok(t) => {
            debug!("encoded token: {}", t);
            Ok(t)
        },
        Err(e) => {
            error!("can not encode token - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

fn get_encoding_key(sign_key: &Vec<u8>) -> Result<EncodingKey, Status> {
    match EncodingKey::from_ec_pem(sign_key) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not create encoding key - cause {:?}", e);
            Err(Status::InternalServerError)
        }
    }
}

fn get_sign_key(config: &Config) -> Result<Vec<u8>, Status> {
    match read_sign_key(config) {
        Ok(key) => Ok(key),
        Err(e) => {
            error!("can not get sign key - cause {}", e);
            Err(Status::InternalServerError)
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