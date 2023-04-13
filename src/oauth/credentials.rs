use chrono::Utc;
use rocket::http::Status;
use rocket::Route;
use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use uuid::Uuid;
use crate::auth::crypto;
use crate::database::AuthDB;
use crate::oauth::credentials::UpdateStatusError::{CONFLICT, INTERNAL};
use crate::oauth::dto::{OAuthCredentialCreateRequestDTO, OAuthCredentialCreateResponseDTO, OAuthCredentialDTO, OAuthCredentialUpdateRequestDTO};
use crate::oauth::model::{OAuthCredential, OAuthCredentialCreateForm, OAuthCredentialStatus, OAuthCredentialUpdateForm};
use crate::users::model::User;

pub fn get_routes() -> Vec<Route> {
    routes![get_by_user, get_by_id, create, update, activate, suspend, revoke, delete]
}

#[post("/", data = "<dto>", format = "application/json")]
async fn create(mut conn: Connection<AuthDB>, user: User,
                dto: Json<OAuthCredentialCreateRequestDTO>) -> Result<Json<OAuthCredentialCreateResponseDTO>, Status> {
    debug!("creating oauth credential {:?} for user {}", dto, user.id);
    let secret = crypto::generate_secure_secret();
    let client_id = Uuid::new_v4().to_string();
    let hashed_secret = crypto::hash_secret(&secret).map_err(|e| {
        error!("can not hash secret - cause: {}", e);
        Status::InternalServerError
    })?;
    let form = OAuthCredentialCreateForm {
        user_id: user.id,
        client_id: &client_id,
        client_secret: &hashed_secret,
        algorithm: "argon2id",
        status: OAuthCredentialStatus::ACTIVE,
        last_used: None,
        expire_at: dto.expire_at,
    };
    match OAuthCredential::insert(&form, &mut conn).await {
        Ok(credential) => {
            info!("oauth credential created successfully with id {}", credential.id);
            let mut res: OAuthCredentialCreateResponseDTO = credential.into();
            res.client_secret = Some(secret);
            Ok(Json(res))
        },
        Err(e) => {
            error!("can not create oauth credential - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/<id>")]
async fn get_by_id(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Json<OAuthCredentialDTO>, Status> {
    debug!("getting by id {}", id);
    secure_get_by_id(&mut conn, id, &user).await
        .map(|credential| Json(credential.into()))
}

#[get("/")]
async fn get_by_user(mut conn: Connection<AuthDB>, user: User) -> Result<Json<Vec<OAuthCredentialDTO>>, Status> {
    debug!("getting by user: {}", user.id);
    match OAuthCredential::find_by_user_id(user.id, &mut conn).await {
        Ok(credentials) => Ok(Json(credentials.into_iter()
            .map(|credential| credential.into())
            .collect::<Vec<OAuthCredentialDTO>>())),
        Err(e) => {
            error!("can not get oauth credential of user {} - cause: {}", user.id, e);
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
async fn update(mut conn: Connection<AuthDB>, id: i64, user: User,
                dto: Json<OAuthCredentialUpdateRequestDTO>) -> Result<Status, Status> {
    debug!("updating oauth credential {}", id);
    let credential = secure_get_by_id(&mut conn, id, &user).await?;
    let new_status: OAuthCredentialStatus = dto.status.into();
    if !check_status_for_update(&credential, new_status) {
        return Err(Status::Conflict);
    }
    let form = OAuthCredentialUpdateForm {
        status: new_status,
        expire_at: dto.expire_at,
    };
    match OAuthCredential::update(id, credential.version, &form, &mut conn).await {
        Ok(n) if n > 0 => {
            info!("user {} has updated oauth credential {}", user.id, credential.id);
            Ok(Status::NoContent)
        },
        Ok(_) => {
            warn!("oauth credential {} not found or optimistic locking has failed", credential.id);
            Err(Status::Conflict)
        },
        Err(e) => {
            error!("can not update oauth credential {} - cause: {}", credential.id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[delete("/<id>")]
async fn delete(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Status, Status> {
    debug!("deleting oauth credential {}", id);
    let credential = secure_get_by_id(&mut conn, id, &user).await?;
    match OAuthCredential::delete(id, &mut conn).await {
        Ok(n) if n > 0 => {
            info!("user {} has deleted oauth credential {}", user.id, credential.id);
            Ok(Status::NoContent)
        },
        Ok(_) => {
            warn!("oauth credential {} not found", id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not delete oauth credential {} - cause: {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn secure_get_by_id(conn: &mut Connection<AuthDB>, id: i64, user: &User) -> Result<OAuthCredential, Status> {
    trace!("secure getById {} for user {}", id, user.id);
    let credential = try_get_by_id(conn, id).await?;
    if credential.user_id == user.id {
        info!("user {} is authorized to access oauth credential {}", user.id, credential.id);
        Ok(credential)
    } else {
        warn!("user {} tried to access oauth credential {} which belong to user {}", user.id, credential.id, credential.user_id);
        Err(Status::Forbidden)
    }
}

async fn try_get_by_id(conn: &mut Connection<AuthDB>, id: i64) -> Result<OAuthCredential, Status> {
    match OAuthCredential::find_by_id(id, conn).await {
        Ok(Some(credential)) => Ok(credential),
        Ok(None) => {
            warn!("oauth credential {} not found", id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not get oauth credential {} - cause: {}", id, e);
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
    if credential.expire_at.is_some() && new_status != OAuthCredentialStatus::EXPIRED && Utc::now() >= credential.expire_at.unwrap() {
        error!("can not update credential {} status - is expired", credential.id);
        return false;
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