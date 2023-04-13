use rocket::Build;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use crate::auth::crypto;
use crate::database::AuthDB;
use crate::users::dto::{UserDTO, UserUpdatePwdDTO};
use crate::users::model::{User, UserForm};

pub mod model;
pub mod dto;

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/users", routes![create, update, update_pwd, delete, get_by_id,
        get_me, update_me, update_me_pwd, delete_me])
}

#[post("/", data = "<dto>", format = "application/json")]
async fn create(mut conn: Connection<AuthDB>, dto: Json<UserDTO>) -> Result<Json<UserDTO>, Status> {
    debug!("creating user {}", dto.email);
    let res = User::find_by_email(&dto.email, &mut conn).await;
    match res {
        Ok(opt) => {
            match opt {
                Some(user) => {
                    warn!("user {} already present", user.email);
                    Err(Status::BadRequest)
                },
                None => {
                    debug!("user not present");
                    do_create(&mut conn, &dto).await.map(|user| user.into())
                }
            }
        },
        Err(e) => {
            error!("can not read user - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[post("/<id>", data = "<dto>", format = "application/json")]
async fn update(mut conn: Connection<AuthDB>, id: i64, user: User, dto: Json<UserDTO>) -> Result<Json<UserDTO>, Status> {
    debug!("updating user {}", id);
    let result = User::find_by_id(id, &mut conn).await;
    match result {
        Ok(opt) if user.id == id && opt.is_some() => {
            do_update(&mut conn, &opt.unwrap(), id, &dto).await.map(|u| u.into())
        },
        Ok(opt) if opt.is_none() => {
            warn!("user {} not found", id);
            Err(Status::NotFound)
        },
        Ok(_) => {
            warn!("user {} tried to access private data of the user {}", user.id, id);
            Err(Status::Forbidden)
        },
        Err(e) => {
            error!("can not update user {} - cause {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[post("/<id>/pwd", data="<dto>", format = "application/json")]
async fn update_pwd(mut conn: Connection<AuthDB>, id: i64, user: User, dto: Json<UserUpdatePwdDTO<'_>>) -> Status {
    debug!("updating pwd of user {}", id);
    let result = User::find_by_id(id, &mut conn).await;
    match result {
        Ok(opt) if user.id == id && opt.is_some() => {
            do_update_pwd(&mut conn, &user, id, &dto).await
        },
        Ok(opt) if opt.is_none() => {
            warn!("user {} not found", id);
            Status::NotFound
        },
        Ok(_) => {
            warn!("user {} tried to access private data of the user {}", user.id, id);
            Status::Forbidden
        },
        Err(e) => {
            error!("can not update user {} - cause {}", id, e);
            Status::InternalServerError
        }
    }
}

#[delete("/<id>")]
async fn delete(mut conn: Connection<AuthDB>, id: i64, user: User) -> Status {
    debug!("deleting user {}", id);
    if user.id != id {
        warn!("user {} tried to access private data of the user {}", user.id, id);
        return Status::Forbidden;
    }
    do_delete(&mut conn, &user, id).await
}

#[get("/<id>")]
async fn get_by_id(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Json<UserDTO>, Status> {
    debug!("reading one by id {}", id);
    let result = User::find_by_id(id, &mut conn).await;
    match result {
        Ok(opt) if user.id == id && opt.is_some() => {
            Ok(Json(opt.unwrap().into()))
        },
        Ok(opt) if opt.is_none() => {
            warn!("user {} not found", id);
            Err(Status::NotFound)
        },
        Ok(_) => {
            warn!("user {} tried to access private data of the user {}", user.id, id);
            Err(Status::Forbidden)
        }
        Err(e) => {
            error!("can not read user {} - cause {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/me")]
async fn get_me(user: User) -> Result<Json<UserDTO>, Status> {
    debug!("get me - user {}", user.id);
    Ok(Json(user.into()))
}

#[post("/me", data = "<dto>", format = "application/json")]
async fn update_me(mut conn: Connection<AuthDB>, user: User, dto: Json<UserDTO>) -> Result<Json<UserDTO>, Status> {
    debug!("update me - user {}", user.id);
    do_update(&mut conn, &user, user.id, &dto).await.map(|u| u.into())
}

#[post("/me/pwd", data = "<dto>", format = "application/json")]
async fn update_me_pwd(mut conn: Connection<AuthDB>, user: User, dto: Json<UserUpdatePwdDTO<'_>>) -> Status {
    debug!("update me pwd - user {}", user.id);
    do_update_pwd(&mut conn, &user, user.id, &dto).await
}

#[delete("/me")]
async fn delete_me(mut conn: Connection<AuthDB>, user: User) -> Status {
    debug!("delete me - user {}", user.id);
    do_delete(&mut conn, &user, user.id).await
}

async fn do_create(conn: &mut Connection<AuthDB>, dto: &UserDTO) -> Result<UserDTO, Status> {
    if dto.password.is_none() {
        return Err(Status::BadRequest);
    }
    let hashed_pwd = crypto::hash_pwd(dto.password.as_ref().unwrap());
    match hashed_pwd {
        Some(h) => {
            let form = UserForm {
                email: dto.email.to_string(),
                password: h,
                algorithm: "scrypt".to_string(),
                last_login: None
            };
            match User::insert(&form, conn).await {
                Ok(user) => {
                    info!("user created successfully with id {}", user.id);
                    Ok(user.into())
                },
                Err(e) => {
                    error!("can not create user - cause {}", e);
                    Err(Status::InternalServerError)
                }
            }
        },
        None => {
            error!("can not create user - hash password failure");
            Err(Status::InternalServerError)
        }
    }
}

async fn do_update(conn: &mut Connection<AuthDB>, user: &User, id: i64, dto: &UserDTO) -> Result<UserDTO, Status> {
    let form = UserForm {
        email: dto.email.to_string(),
        password: String::new(),
        algorithm: String::new(),
        last_login: None
    };
    let result = User::update(id, &form, conn).await;
    match result {
        Ok(n) if n > 0 => {
            info!("user {} has updated user {}", user.id, id);
            let user = User::find_by_id(id, conn).await.map_err(|e| {
                error!("can not get user after update - cause {}", e);
                Status::InternalServerError
            });
            match user {
                Ok(opt) => {
                    opt.map_or(Err(Status::NotFound), |u| Ok(u.into()))
                },
                Err(e) => Err(e)
            }
        },
        Ok(_) => {
            warn!("can not update - user {} not found", id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not update user {} - cause {}", user.id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn do_update_pwd(conn: &mut Connection<AuthDB>, user: &User, id: i64, dto: &UserUpdatePwdDTO<'_>) -> Status {
    let hashed_pwd = crypto::hash_pwd(dto.password);
    match hashed_pwd {
        Some(h) => {
            let form = UserForm {
                email: String::new(),
                password: h,
                algorithm: "scrypt".to_string(),
                last_login: None
            };
            let result = User::update_password(id, &form, conn).await;
            match result {
                Ok(n) if n > 0 => {
                    info!("user {} has updated password of user {}", user.id, id);
                    Status::NoContent
                },
                Ok(_) => {
                    warn!("user {} not found", id);
                    Status::NotFound
                },
                Err(e) => {
                    error!("can not update user {} - cause {}", id, e);
                    Status::InternalServerError
                }
            }
        },
        None => Status::InternalServerError
    }
}

async fn do_delete(conn: &mut Connection<AuthDB>, user: &User, id: i64) -> Status {
    let result = User::delete(id, conn).await;
    match result {
        Ok(n) if n > 0 => {
            info!("user {} has deleted user {}", user.id, id);
            Status::NoContent
        },
        Ok(_) => {
            warn!("user {} not found", id);
            Status::NotFound
        },
        Err(e) => {
            error!("can not delete user {} - cause {}", id, e);
            Status::InternalServerError
        }
    }
}
