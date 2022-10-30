#[macro_use] extern crate rocket;
#[macro_use] extern crate log;

use std::path::Path;
use jsonwebtoken::{Algorithm, decode, DecodingKey, Validation};
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::outcome::Outcome::{Failure, Success};
use rocket::request::{self, Request, FromRequest};
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::State;
use rocket_db_pools::{Connection, Database};
use rocket_dyn_templates::Template;
use uuid::Uuid;
use crate::database::AuthDB;
use crate::users::dto::UserDTO;
use crate::users::model::{User, UserForm};

mod controller;
mod base_model;
mod database;

mod web;
mod users;
mod auth;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    pub jwt_key: String,
    pub jwt_exp: u64,
    pub template_dir: String,
    pub static_dir: String
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let path = if cfg!(windows) {
        "log-config.yml"
    } else {
        let path = "/etc/auth-service/log-config.yml";
        if Path::new(path).exists() {
            path
        } else {
            "log-config.yml"
        }
    };
    log4rs::init_file(path, Default::default()).unwrap();

    let mut my_rocket = rocket::build();

    let figment = my_rocket.figment();
    let config: Config = figment.extract().expect("config");
    info!("CONFIG: {:?}", config);

    my_rocket = web::mount(my_rocket);
    my_rocket = users::mount(my_rocket);
    my_rocket = auth::mount(my_rocket);
    let _ = my_rocket.mount("/test", routes!(test))
        .attach(AdHoc::config::<Config>())
        .attach(AuthDB::init())
        .attach(Template::fairing())
        .launch()
        .await?;
    Ok(())
}

#[get("/")]
async fn test(config: &State<Config>, mut conn: Connection<AuthDB>/*, token: AuthToken*/) -> Json<UserDTO> {
    info!("CONFIG: {:?}", config);
    //info!("TOKEN: {:?}", token);

    info!("TEST DB: {:?}", User::find_all(&mut conn).await);
    info!("TEST DB findByMail: {:?}", User::find_by_email("random mail", &mut conn).await.err().unwrap());
    info!("TEST DB: {:?}", User::find_by_id(1, &mut conn).await);

    let form = UserForm {
        email: Uuid::new_v4().to_string(),
        password: "".to_string(),
        algorithm: "".to_string(),
        last_login: None
    };
    info!("INSERT: {:?}", User::insert(&form, &mut conn).await);

    Json(User::find_by_id(1, &mut conn).await.unwrap().unwrap().into())
}

#[derive(Debug)]
pub enum AuthTokenError {
    BadCount,
    Missing,
    Invalid,
    Broken
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthToken {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthToken { // TODO &'r AuthToken
    type Error = AuthTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        info!("CONFIG: {:?} ", request.rocket().config());
        info!("CONFIG: {:?}", request.guard::<&rocket::Config>().await.unwrap());
        let config = request.rocket().state::<Config>().unwrap();
        match keys.len() {
            0 => {
                warn!("Access denied! Missing token.");
                Failure((Status::Unauthorized, Self::Error::Missing))
            }
            1 => match read_token(keys[0], &config.jwt_key) {
                Ok(token) => {
                    debug!("token is valid");
                    Success(token)
                },
                Err(_) => {
                    warn!("Access denied! Invalid token.");
                    Failure((Status::Unauthorized, Self::Error::Invalid))
                }
            }
            _ => {
                warn!("Access denied! Too many tokens.");
                Failure((Status::Unauthorized, Self::Error::BadCount))
            }
        }
    }
}

fn read_token(header: &str, secret: &String) -> Result<AuthToken, String> {
    let keys = header.split("Bearer ").collect::<Vec<&str>>();
    if keys.len() != 2 || keys[1].len() == 0 {
        error!("token invalid {:?}", header);
        return Err("Token not valid!".to_string());
    }
    let decode_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS512);
    let token = decode::<AuthToken>(keys[1], &decode_key, &validation);
    match token {
        Ok(t) => Ok(t.claims),
        Err(e) => {
            error!("token invalid {}", e);
            Err("Token not valid!".to_string())
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = AuthTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let mut conn = request.guard::<Connection<AuthDB>>().await.unwrap();
        let token_outcome = request.guard::<AuthToken>().await;
        if token_outcome.is_failure() {
            // forward failure from AuthToken handler
            return Failure(token_outcome.failed().unwrap());
        }
        let token = token_outcome.unwrap();
        let user = User::find_by_id(token.sub, &mut conn).await;
        match user {
            Ok(opt) if opt.is_some() => {
                let user = opt.unwrap();
                debug!("access granted to user {}", user.id);
                Success(user)
            },
            Ok(_) => {
                warn!("Access denied! User {} not found", token.sub);
                Failure((Status::Unauthorized, Self::Error::Broken))
            },
            Err(e) => {
                warn!("Access denied! User {} - cause {}", token.sub, e);
                Failure((Status::Unauthorized, Self::Error::Broken))
            }
        }
    }
}

pub struct Prefix {
    pub prefix: String
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Prefix {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Prefix, Self::Error> {
        let values: Vec<_> = request.headers().get("X-Forwarded-Prefix").collect();
        match values.len() {
            0 => {
                info!("prefix header: None");
                Success(Prefix {
                    prefix: "".to_string()
                })
            }
            1 => {
                let str = values[0].to_string();
                info!("prefix header: {}", str);
                Success(Prefix {
                    prefix: str
                })
            }
            _ => {
                warn!("prefix header: too many");
                Success(Prefix {
                    prefix: "".to_string()
                })
            }
        }
    }
}
