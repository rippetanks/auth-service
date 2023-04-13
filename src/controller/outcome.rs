use rocket::{Request, request};
use rocket::http::Status;
use rocket::outcome::Outcome::{Failure, Success};
use rocket::request::FromRequest;
use rocket_db_pools::Connection;
use crate::auth::token;
use crate::auth::token::{AuthToken, AuthTokenError};
use crate::config::Config;
use crate::controller::Prefix;
use crate::database::AuthDB;
use crate::users::model::User;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthToken { // TODO &'r AuthToken
    type Error = AuthTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        let config = request.rocket().state::<Config>().unwrap();
        match keys.len() {
            0 => {
                warn!("Access denied! Missing token.");
                Failure((Status::Unauthorized, Self::Error::Missing))
            }
            1 => match read_jwt_from_header(keys[0], &config.jwt_key) {
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

const AUTH_HEADER_NOT_VALID: &str = "Invalid authorization header!";

fn read_jwt_from_header(header: &str, secret: &String) -> Result<AuthToken, &'static str> {
    let headers = header.split("Bearer ").collect::<Vec<&str>>();
    if headers.len() != 2 || headers[1].len() == 0 {
        warn!("Invalid authorization header: {}", header);
        return Err(AUTH_HEADER_NOT_VALID);
    }
    token::read_jwt(headers[1], secret)
}
