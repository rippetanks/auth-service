//use diesel::PgConnection;
//use rocket::fairing::AdHoc;
//use rocket::http::Status;
//use rocket::request::{self, FromRequest, Request};
//use rocket::outcome::{try_outcome, Outcome::*};
//use rocket::serde::{Serialize, Deserialize};
//use jsonwebtoken::{decode, Algorithm, Validation, DecodingKey};
//use rocket::{Build, Rocket, State};
//use rocket_dyn_templates::Template;

//use crate::database::AuthServiceDB;
//use crate::users;
//use crate::web;
//use crate::users::model::User;


use rocket::{Build, Rocket};

//#[derive(Debug, Deserialize)]
//#[serde(crate = "rocket::serde")]
pub struct Config {
    //pub jwt_key: String,
    //pub jwt_exp: i32,
    pub template_dir: String,
    pub static_dir: String
}

pub struct JwtConfig {
    pub jwt_key: String,
    pub jwt_exp: u64
}

/*#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthToken {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize
}*/
/*
#[derive(Debug)]
pub struct Prefix {
    pub prefix: String
}
*/
/*
#[derive(Debug)]
pub enum AuthTokenError {
    BadCount,
    Missing,
    Invalid,
    Broken
}
*/

/*#[launch]
pub fn init() -> Rocket<Build> {
    rocket::build()
        .mount("/test", routes!(test))
    //let figment = rocket.figment();

    //let config: Config = figment.extract().expect("config");

    //rocket
        //.attach(AuthServiceDB::fairing())
        //.attach(Template::fairing())
        //.attach(AdHoc::config::<Config>())
        //.mount("/", routes![test])
}*/

/*#[get("/")]
async fn test(/*token: &AuthToken*//*, config: &State<Config>*/) {
   // info!("{:?} {:?}", token, config);
}*/

/*
fn fairing_extra() -> AdHoc {
    AdHoc::on_ignite("Extras Fairing", |r| async move {
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
*/

/*fn read_token(header: &str, secret: &String) -> Result<AuthToken, String> {
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
}*/

/*#[rocket::async_trait]
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
}*/

/*#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r AuthToken {
    type Error = AuthTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        let extra = request.guard::<&State<JwtConfig>>().await.unwrap();
        match keys.len() {
            0 => {
                warn!("Access denied! Missing token.");
                Failure((Status::Unauthorized, Self::Error::Missing))
            }
            1 => match read_token(keys[0], &extra.jwt_key) {
                Ok(token) => {
                    debug!("token is valid");
                    Success(request.local_cache(|| {
                        token
                    }))
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
}*/

/*#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = AuthTokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let conn = request.guard::<&AuthServiceDB>().await.unwrap();
        let token = try_outcome!(request.guard::<AuthToken>().await);
        let user = User::read_by_id(token.sub, conn);
        match user {
            Ok(user) => {
                debug!("access granted to user {}", user.id);
                Success(user)
            },
            Err(e) => {
                warn!("Access denied! User {}, cause {}", token.sub, e);
                Failure((Status::Unauthorized, Self::Error::Broken))
            }
        }
    }
}*/
