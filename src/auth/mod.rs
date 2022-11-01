use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::{Build, State};
use rocket::http::Status;
use rocket::serde::Deserialize;
use rocket::serde::json::Json;
use rocket::serde::json::serde_json::json;
use rocket_db_pools::Connection;
use crate::config::Config;
use crate::controller::AuthToken;
use crate::database::AuthDB;
use crate::users::model::User;

pub mod crypto;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AuthJSON<'r> {
    email: &'r str,
    password: &'r str
}

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/auth", routes![login])
}

#[post("/login", data = "<json>", format = "application/json")]
async fn login(mut conn: Connection<AuthDB>, config: &State<Config>, json: Json<AuthJSON<'_>>) -> Result<String, Status> {
    let res = User::find_by_email(json.email, &mut conn).await;
    match res {
        Ok(opt) => {
            match opt {
                Some(user) if crypto::hash_check(json.password, user.password.as_str()) => {
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
