
use rocket_contrib::json::Json;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::State;
use diesel::result::Error;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{Header, Algorithm, encode, EncodingKey};

use crate::database::AuthServiceDB;
use crate::controller::{AuthToken, Extras};
use crate::users::model::{User, UserForm};
use crate::base_model::BaseModel;

pub mod model;
mod crypto;

#[derive(Debug,Deserialize)]
struct AuthJSON<'a> {
    email: &'a str,
    password: &'a str
}

#[post("/", data = "<json>", format = "application/json")]
fn create(conn: AuthServiceDB, json: Json<AuthJSON>) -> Result<Status, Status> {
    debug!("create_users");
    let user = User::read_by_email(json.email, &conn);
    user.map_or_else(|e| {
        if e.eq(&Error::NotFound) {
            debug!("user not present");
            crypto::hash_pwd(json.password)
                .map_or_else(|| Err(Status::InternalServerError), |h| {
                    let form = UserForm {
                        email: json.email.to_string(),
                        password: h,
                        algorithm: "scrypt".to_string(),
                        last_login: None
                    };
                    match User::create(&form, &conn) {
                        Ok(user) => {
                            info!("user created successfully (id = {})", user.id);
                            Ok(Status::NoContent)
                        },
                        Err(e) => {
                            error!("can not create user caused by {}", e);
                            Err(Status::InternalServerError)
                        }
                    }
                })
        } else {
            error!("can not read user: {}", e);
            Err(Status::InternalServerError)
        }
    }, |_| {
        info!("user already present");
        Err(Status::BadRequest)
    })
}

#[get("/me")]
fn read_me(mut user: User) -> Result<Json<User>, Status> {
    debug!("read_me");
    User::mask(&mut user);
    Ok(Json(user))
}

#[get("/<id>")]
fn read_one(conn: AuthServiceDB, id: i64, user: User) -> Result<Json<User>, Status> {
    debug!("read_one");
    let result = User::read_by_id(id, &conn);
    match result {
        Ok(mut result) if result.id == user.id => {
            User::mask(&mut result);
            Ok(Json(result))
        },
        Ok(result) => {
            warn!("user {} try to access private date of the user {}", user.id, result.id);
            Err(Status::Forbidden)
        }
        Err(e) => {
            error!("can not read user {}; cause {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}

/* DISABLED FOR SECURITY REASON */
#[allow(dead_code, unreachable_code, unused_variables)]
#[get("/")]
fn read(conn: AuthServiceDB, user: User) -> Result<Json<Vec<User>>, Custom<String>> {
    debug!("read");
    warn!("DISABLED FOR SECURITY REASON");
    let result = User::read(&conn);
    panic!("DISABLED FOR SECURITY REASON");
    User::unpack(result)
}

#[post("/<id>", data = "<json>", format = "application/json")]
fn update(conn: AuthServiceDB, id: i64, user: User, json: Json<AuthJSON>) -> Status {
    debug!("update");
    let to_update = User::read_by_id(id, &conn);
    match to_update {
        Ok(to_update) if user.id != id => {
            do_update(&conn, &to_update, &json)
        },
        Ok(_) => {
            warn!("user {} try to access private date of the user {}", user.id, id);
            Status::Forbidden
        },
        Err(e) if e.eq(&Error::NotFound) => {
            warn!("User not found!");
            Status::NotFound
        },
        Err(e) => {
            error!("Can not update user {}; cause {}", id, e);
            Status::InternalServerError
        }
    }
}

#[post("/me", data = "<json>", format = "application/json")]
fn update_me(conn: AuthServiceDB, user: User, json: Json<AuthJSON>) -> Status {
    debug!("update_me");
    do_update(&conn, &user, &json)
}

#[delete("/<id>")]
fn delete(conn: AuthServiceDB, id: i64, user: User) -> Status {
    debug!("delete");
    if user.id != id {
        warn!("user {} try to access private date of the user {}", user.id, id);
        return Status::Forbidden;
    }
    do_delete(&conn, id)
}

#[delete("/me")]
fn delete_me(conn: AuthServiceDB, user: User) -> Status {
    debug!("delete_me");
    do_delete(&conn, user.id)
}

#[post("/login", data = "<json>", format = "application/json")]
fn login(conn: AuthServiceDB, json: Json<AuthJSON>, extras: State<Extras>) -> Result<String, Status> {
    let user = User::read_by_email(json.email, &conn);
    match user {
        Ok(user) if crypto::hash_check(json.password, user.password.as_str()) => {
            let header = Header::new(Algorithm::HS512);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let claims = AuthToken {
                sub: user.id,
                exp: (now + extras.jwt_exp) as usize,
                iat: now as usize
            };
            let encoding_key = EncodingKey::from_secret(extras.jwt_key.as_ref());
            let token = encode(&header, &claims, &encoding_key);
            if token.is_ok() {
                Ok(json!({"token": token.unwrap()}).to_string())
            } else {
                Err(Status::InternalServerError)
            }
        },
        Ok(user) => {
            warn!("Access denied! Wrong password for user {}", user.email);
            Err(Status::Unauthorized)
        },
        Err(e) if e.eq(&Error::NotFound) => {
            warn!("User not found! Can not login user with email {}", json.email);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("Can not login user with email {}; cause {}", json.email, e);
            Err(Status::InternalServerError)
        }
    }
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    rocket.mount("/users", routes![create, read_me, read_one, update, update_me, delete, delete_me, login])
}

fn do_update(conn: &AuthServiceDB, user: &User, json: &AuthJSON) -> Status {
    let hash_pwd = crypto::hash_pwd(json.password);
    match hash_pwd {
        Some(h) => {
            let form = UserForm {
                email: json.email.to_string(),
                password: h,
                algorithm: "scrypt".to_string(),
                last_login: user.last_login
            };
            let result = User::update(user.id, &form, &conn);
            match result {
                Ok(n) if n > 0 => {
                    info!("User {} update user {}", user.id, user.id);
                    Status::NoContent
                },
                Ok(_) => {
                    warn!("User not found!");
                    Status::NotFound
                },
                Err(e) => {
                    error!("Can not update user {}; cause {}", user.id, e);
                    Status::InternalServerError
                }
            }
        },
        None => Status::InternalServerError
    }
}

fn do_delete(conn: &AuthServiceDB, id: i64) -> Status {
    let result = User::delete(id, conn);
    match result {
        Ok(n) if n > 0 => {
            info!("User {} delete user {}", id, id);
            Status::NoContent
        },
        Ok(_) => {
            warn!("User not found!");
            Status::NotFound
        },
        Err(e) => {
            error!("Can not delete user {}; cause {}", id, e);
            Status::InternalServerError
        }
    }
}
