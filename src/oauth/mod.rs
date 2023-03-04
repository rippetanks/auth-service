use chrono::Utc;
use rocket::Build;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use uuid::Uuid;
use crate::auth::crypto;
use crate::database::AuthDB;
use crate::oauth::dto::{OAuthCreateRequestDTO, OAuthCreateResponseDTO, OAuthCredentialDTO, OAuthUpdateRequestDTO};
use crate::oauth::model::{OAuthCredential, OAuthCredentialCreateForm, OAuthCredentialStatus, OAuthCredentialUpdateForm};
use crate::oauth::UpdateStatusError::{CONFLICT, INTERNAL};
use crate::users::model::User;

pub mod model;
pub mod dto;

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/oauth", routes![get_by_user, get_by_id, create, update,
        activate, suspend, revoke, delete])
}

#[post("/", data = "<dto>", format = "application/json")]
async fn create(mut conn: Connection<AuthDB>, user: User, dto: Json<OAuthCreateRequestDTO>) -> Result<Json<OAuthCreateResponseDTO>, Status> {
    debug!("creating oauth credential {:?} for user {}", dto, user.id);
    let secret = crypto::generate_secure_secret();
    let form = OAuthCredentialCreateForm {
        user_id: user.id,
        client_id: Uuid::new_v4().to_string(),
        client_secret: crypto::hash_secret(&secret).unwrap(),
        algorithm: "argon2id".to_string(),
        status: OAuthCredentialStatus::ACTIVE,
        last_used: None,
        expire_at: dto.expire_at,
    };
    match OAuthCredential::insert(&form, &mut conn).await {
        Ok(credential) => {
            info!("oauth credential created successfully with id {}", credential.id);
            let mut res: OAuthCreateResponseDTO = credential.into();
            res.client_secret = Some(secret);
            Ok(Json(res))
        },
        Err(e) => {
            error!("can not create oauth credential - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/<id>")]
async fn get_by_id(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Json<OAuthCredentialDTO>, Status> {
    debug!("reading one by id {}", id);
    secure_get_by_id(&mut conn, id, &user).await
        .map(|credential| Json(credential.into()))
}

#[get("/")]
async fn get_by_user(mut conn: Connection<AuthDB>, user: User) -> Result<Json<Vec<OAuthCredentialDTO>>, Status> {
    debug!("reading all by user: {}", user.id);
    match OAuthCredential::find_by_user_id(user.id, &mut conn).await {
        Ok(credentials) => Ok(Json(credentials.into_iter()
            .map(|credential| credential.into())
            .collect::<Vec<OAuthCredentialDTO>>())),
        Err(e) => {
            error!("can not get oauth credential of user {} - cause {}", user.id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[patch("/<id>/activate")]
async fn activate(mut conn: Connection<AuthDB>, id: i64, user: User) -> Status {
    debug!("activating oauth credential {}", id);
    update_status_by_id(&mut conn, id, &user, OAuthCredentialStatus::ACTIVE).await
}

#[patch("/<id>/suspend")]
async fn suspend(mut conn: Connection<AuthDB>, id: i64, user: User) -> Status {
    debug!("suspending oauth credential {}", id);
    update_status_by_id(&mut conn, id, &user, OAuthCredentialStatus::SUSPENDED).await
}

#[patch("/<id>/revoke")]
async fn revoke(mut conn: Connection<AuthDB>, id: i64, user: User) -> Status {
    debug!("revoking oauth credential {}", id);
    update_status_by_id(&mut conn, id, &user, OAuthCredentialStatus::REVOKED).await
}

#[put("/<id>", data = "<dto>", format = "application/json")]
async fn update(mut conn: Connection<AuthDB>, id: i64, user: User, dto: Json<OAuthUpdateRequestDTO>) -> Status {
    debug!("updating oauth credential {}", id);
    match secure_get_by_id(&mut conn, id, &user).await {
        Ok(credential) => {
            let new_status: OAuthCredentialStatus = dto.status.into();
            if !check_status_for_update(&credential, new_status) {
                return Status::Conflict;
            }
            let form = OAuthCredentialUpdateForm {
                status: new_status,
                expire_at: dto.expire_at,
            };
            match OAuthCredential::update(id, credential.version, &form, &mut conn).await {
                Ok(n) if n > 0 => {
                    info!("user {} has updated oauth credential {}", user.id, credential.id);
                    Status::NoContent
                },
                Ok(_) => {
                    warn!("oauth credential {} not found or optimistic locking has failed", credential.id);
                    Status::Conflict
                },
                Err(e) => {
                    error!("can not update oauth credential {} - cause {}", id, e);
                    Status::InternalServerError
                }
            }
        },
        Err(e) => e
    }
}

#[delete("/<id>")]
async fn delete(mut conn: Connection<AuthDB>, id: i64, user: User) -> Status {
    debug!("deleting oauth credential {}", id);
    match secure_get_by_id(&mut conn, id, &user).await {
        Ok(_) => {
            match OAuthCredential::delete(id, &mut conn).await {
                Ok(n) if n > 0 => {
                    info!("user {} has deleted oauth credential {}", user.id, id);
                    Status::NoContent
                },
                Ok(_) => {
                    warn!("oauth credential {} not found", id);
                    Status::NotFound
                },
                Err(e) => {
                    error!("can not delete oauth credential {} - cause {}", id, e);
                    Status::InternalServerError
                }
            }
        },
        Err(e) => e
    }
}

async fn secure_get_by_id(conn: &mut Connection<AuthDB>, id: i64, user: &User) -> Result<OAuthCredential, Status> {
    match OAuthCredential::find_by_id(id, conn).await {
        Ok(opt) => {
            match opt {
                Some(credential) if credential.user_id == user.id => {
                    Ok(credential)
                },
                Some(credential) => {
                    warn!("user {} tried to access oauth credential {} which belong to user {}", user.id, credential.id, credential.user_id);
                    Err(Status::Forbidden)
                },
                None => {
                    warn!("oauth credential {} not found", id);
                    Err(Status::NotFound)
                }
            }
        }
        Err(e) => {
            error!("can not update status oauth credential {} - cause {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[derive(Debug, PartialEq)]
enum UpdateStatusError {
    CONFLICT,
    INTERNAL
}

impl UpdateStatusError {
    fn to_status(self) -> Status {
        match self {
            CONFLICT => Status::Conflict,
            INTERNAL => Status::InternalServerError,
        }
    }
}

async fn update_status_by_id(conn: &mut Connection<AuthDB>, id: i64, user: &User, new_status: OAuthCredentialStatus) -> Status {
    match secure_get_by_id(conn, id, user).await {
        Ok(credential) => {
            match update_status(conn, credential, new_status).await {
                Ok(_) => Status::NoContent,
                Err(e) => e.to_status()
            }
        }
        Err(e) => e
    }
}

fn check_status_for_update(credential: &OAuthCredential, new_status: OAuthCredentialStatus) -> bool {
    if credential.expire_at.is_some() && new_status != OAuthCredentialStatus::EXPIRED {
        let now = Utc::now();
        if now >= credential.expire_at.unwrap() {
            error!("can not update credential {} status - is expired", credential.id);
            return false;
        }
    }
    if new_status == OAuthCredentialStatus::SUSPENDED && credential.status != OAuthCredentialStatus::ACTIVE {
        error!("can not update credential {} status from {:?} to {:?}", credential.id, credential.status, new_status);
        return false;
    }
    if new_status == OAuthCredentialStatus::ACTIVE && credential.status != OAuthCredentialStatus::SUSPENDED {
        error!("can not update credential {} status from {:?} to {:?}", credential.id, credential.status, new_status);
        return false;
    }
    if new_status == OAuthCredentialStatus::REVOKED &&
        (credential.status == OAuthCredentialStatus::EXPIRED || credential.status != OAuthCredentialStatus::REVOKED) {
        error!("can not update credential {} status from {:?} to {:?}", credential.id, credential.status, new_status);
        return false;
    }
    return true;
}

async fn update_status(conn: &mut Connection<AuthDB>, credential: OAuthCredential, new_status: OAuthCredentialStatus) -> Result<(), UpdateStatusError> {
    if !check_status_for_update(&credential, new_status) {
        return Err(CONFLICT);
    }
    match OAuthCredential::update_status(credential.id, credential.version, &new_status, conn).await {
        Ok(n) if n > 0 => {
            info!("update credential {} status from {:?} to {:?}", credential.id, credential.status, new_status);
            Ok(())
        },
        Ok(_) => {
            error!("oauth credential {} not found or optimistic locking has failed", credential.id);
            Err(CONFLICT)
        }
        Err(e) => {
            error!("can not update credential {} status from {:?} to {:?} - cause {}", credential.id, credential.status, new_status, e);
            Err(INTERNAL)
        }
    }
}
