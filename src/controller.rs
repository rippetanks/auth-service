
use rocket_contrib::templates::Template;
use rocket::error::LaunchError;
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::request::{FromRequest, Request, Outcome, State};
use serde::{Serialize, Deserialize};
use jsonwebtoken::{decode, Algorithm, Validation, DecodingKey};

use crate::database::AuthServiceDB;
use crate::users;
use crate::web;
use crate::users::model::User;

#[derive(Debug)]
pub struct Extras {
    pub jwt_key: String,
    pub jwt_exp: u64,
    pub template_dir: String,
    pub static_dir: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize
}

#[derive(Debug)]
pub struct Prefix {
    pub prefix: String
}

#[derive(Debug)]
pub enum AuthTokenError {
    BadCount,
    Missing,
    Invalid,
    Broken
}

pub fn init() -> LaunchError {
    let mut r = rocket::ignite()
        .attach(AuthServiceDB::fairing())
        .attach(Template::fairing())
        .attach(fairing_extra());
    r = users::mount(r);
    r = web::mount(r);
    r.launch()
}

fn fairing_extra() -> rocket::fairing::AdHoc {
    AdHoc::on_attach("Extras Fairing", |r| {
        let config = r.config();
        let jwt_key = config.get_str("jwt_key").unwrap().to_string();
        let jwt_exp = config.get_int("jwt_exp").unwrap() as u64;
        let t_dir = config.get_string("template_dir").unwrap().to_string();
        let s_dir = config.get_string("static_dir").unwrap().to_string();
        Ok(r.manage(Extras {
            jwt_key,
            jwt_exp,
            template_dir: t_dir,
            static_dir: s_dir
        }))
    })
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

impl<'a, 'r> FromRequest<'a, 'r> for Prefix {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Prefix, Self::Error> {
        let values: Vec<_> = request.headers().get("X-Forwarded-Prefix").collect();
        match values.len() {
            0 => {
                info!("prefix header: None");
                Outcome::Success(Prefix {
                    prefix: "".to_string()
                })
            }
            1 => {
                let str = values[0].to_string();
                info!("prefix header: {}", str);
                Outcome::Success(Prefix {
                    prefix: str
                })
            }
            _ => {
                warn!("prefix header: too many");
                Outcome::Success(Prefix {
                    prefix: "".to_string()
                })
            }
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthToken {
    type Error = AuthTokenError;

    fn from_request(request: &'a Request<'r>) -> Outcome<AuthToken, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        let extra = request.guard::<State<Extras>>().unwrap();
        match keys.len() {
            0 => {
                warn!("Access denied! Missing token.");
                Outcome::Failure((Status::Unauthorized, Self::Error::Missing))
            }
            1 => match read_token(keys[0], &extra.jwt_key) {
                Ok(token) => {
                    debug!("token is valid");
                    Outcome::Success(token)
                },
                Err(_) => {
                    warn!("Access denied! Invalid token.");
                    Outcome::Failure((Status::Unauthorized, Self::Error::Invalid))
                }
            }
            _ => {
                warn!("Access denied! Too many tokens.");
                Outcome::Failure((Status::Unauthorized, Self::Error::BadCount))
            }
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = AuthTokenError;

    fn from_request(request: &'a Request<'r>) -> Outcome<User, Self::Error> {
        let conn = request.guard::<AuthServiceDB>().unwrap();
        let token_outcome = request.guard::<AuthToken>();
        if token_outcome.is_failure() {
            // forward failure from AuthToken handler
            return Outcome::Failure(token_outcome.failed().unwrap());
        }
        let token = token_outcome.unwrap();
        let user = User::read_by_id(token.sub, &conn);
        match user {
            Ok(user) => {
                debug!("access granted to user {}", user.id);
                Outcome::Success(user)
            },
            Err(e) => {
                warn!("Access denied! User {}, cause {}", token.sub, e);
                Outcome::Failure((Status::Unauthorized, Self::Error::Broken))
            }
        }
    }
}
