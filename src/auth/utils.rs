use std::fs::File;
use std::io::{BufReader, Error, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::Utc;
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::http::Status;
use rocket_db_pools::Connection;
use crate::config::Config;
use crate::controller::AuthToken;
use crate::database::AuthDB;
use crate::oauth::model::{OAuthCredential, OAuthCredentialStatus};

pub fn create_oauth2_token(credential: &OAuthCredential, config: &Config) -> Result<String, Status> {
    let header = Header::new(Algorithm::ES384);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = AuthToken {
        sub: credential.user_id,
        exp: (now + config.oauth_jwt_exp) as usize,
        iat: now as usize
    };
    let sign_key = get_sign_key(config)?;
    let encoding_key = get_encoding_key(&sign_key)?;
    get_token(&header, &claims, &encoding_key)
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

async fn try_get_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<Option<OAuthCredential>, Status> {
    match OAuthCredential::find_by_client_id(client_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get oauth credential by client_id {} - cause {}", client_id, e);
            Err(Status::InternalServerError)
        }
    }
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