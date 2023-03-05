use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::{Build, State};
use rocket::form::Form;
use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::serde::json::serde_json::json;
use rocket_db_pools::Connection;
use crate::auth::http_basic_auth::HttpBasicAuth;
use crate::auth::utils::{create_oauth2_token, get_by_client_id};
use crate::config::Config;
use crate::controller::AuthToken;
use crate::database::AuthDB;
use crate::oauth::model::OAuthCredential;
use crate::users::model::User;

pub mod crypto;

mod http_basic_auth;
mod utils;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AuthJSON<'r> {
    email: &'r str,
    password: &'r str
}

#[derive(Debug, FromForm)]
struct OAuth2TokenRequest<'r> {
    grant_type: &'r str
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
struct OAuth2TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64
}

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/auth", routes![login, oauth2_token])
}

#[post("/login", data = "<json>", format = "application/json")]
async fn login(mut conn: Connection<AuthDB>, config: &State<Config>, json: Json<AuthJSON<'_>>) -> Result<String, Status> {
    match User::find_by_email(json.email, &mut conn).await {
        Ok(opt) => {
            match opt {
                Some(user) if crypto::hash_pwd_check(json.password, user.password.as_str()) => {
                    let header = Header::new(Algorithm::HS512);
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    let claims = AuthToken {
                        sub: user.id,
                        exp: (now + config.jwt_exp) as usize,
                        iat: now as usize
                    };
                    let encoding_key = EncodingKey::from_secret(config.jwt_key.as_ref());
                    let token = encode(&header, &claims, &encoding_key);
                    if token.is_ok() {
                        if User::update_last_login(user.id, &mut conn).await.is_err() {
                            error!("can not update last login of user {}", user.id);
                        }
                        Ok(json!({"token": token.unwrap()}).to_string())
                    } else {
                        Err(Status::InternalServerError)
                    }
                },
                Some(_) => {
                    warn!("Access denied! Wrong password for user {}", json.email);
                    Err(Status::Unauthorized)
                },
                None => {
                    warn!("user {} not found", json.email);
                    Err(Status::Unauthorized)
                }
            }
        },
        Err(e) => {
            error!("can not login user with email {} - cause {}", json.email, e);
            Err(Status::InternalServerError)
        }
    }
}

#[post("/oauth2/token", data = "<body>")]
async fn oauth2_token(mut conn: Connection<AuthDB>, config: &State<Config>, body: Form<OAuth2TokenRequest<'_>>, auth: HttpBasicAuth) -> Result<Json<OAuth2TokenResponse>, Status> {
    info!("{:?} {:?}", body, auth);
    match body.grant_type {
        "client_credentials" => {
            let credential = get_by_client_id(&mut conn, &auth.client_id).await?;
            if crypto::hash_secret_check(&auth.client_secret, &credential.client_secret) {
                let token = create_oauth2_token(&credential, &config)?;
                if OAuthCredential::update_last_used(credential.id, &mut conn).await.is_err() {
                    error!("can not update last used of oauth credential {}", credential.id);
                }
                Ok(Json(OAuth2TokenResponse {
                    access_token: token,
                    token_type: "bearer".to_string(),
                    expires_in: config.oauth_jwt_exp,
                }))
            } else {
                warn!("Access denied! Wrong oauth credential for client_id {}", auth.client_id);
                Err(Status::Unauthorized)
            }
        },
        _ => {
            warn!("grant type {} not supported", body.grant_type);
            Err(Status::BadRequest)
        }
    }
}
