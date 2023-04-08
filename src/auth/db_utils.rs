use chrono::Utc;
use rocket::http::Status;
use rocket_db_pools::Connection;
use crate::database::AuthDB;
use crate::oauth::model::{OAuthApp, OAuthCredential, OAuthCredentialStatus};
use crate::users::model::User;

pub async fn get_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<OAuthCredential, Status> {
    match try_get_by_client_id(conn, client_id).await? {
        Some(credential) if credential.status != OAuthCredentialStatus::ACTIVE => {
            warn!("Access denied! oauth credential {} is not active", credential.id);
            Err(Status::Unauthorized)
        },
        Some(credential) if credential.expire_at.is_some() && Utc::now() >= credential.expire_at.unwrap() => {
            warn!("Access denied! oauth credential {} is expired", credential.id);
            Err(Status::Unauthorized)
        },
        Some(credential) => Ok(credential),
        None => {
            warn!("oauth credential not found with client_id {}", client_id);
            Err(Status::NotFound)
        }
    }
}

pub async fn get_app_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<OAuthApp, Status> {
    match try_get_app_by_client_id(conn, client_id).await? {
        Some(app) => Ok(app),
        None => {
            warn!("oauth app not found with client_id {}", client_id);
            Err(Status::NotFound)
        }
    }
}

pub async fn get_user_by_email(conn: &mut Connection<AuthDB>, email: &str) -> Result<User, Status> {
    match try_get_user_by_email(conn, email).await? {
        Some(user) => Ok(user),
        None => {
            warn!("user with email {} not found", email);
            Err(Status::NotFound)
        }
    }
}

pub async fn get_user_by_id(conn: &mut Connection<AuthDB>, id: i64) -> Result<User, Status> {
    match try_get_user_by_id(conn, id).await? {
        Some(user) => Ok(user),
        None => {
            warn!("user with id {} not found", id);
            Err(Status::NotFound)
        }
    }
}

async fn try_get_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<Option<OAuthCredential>, Status> {
    match OAuthCredential::find_by_client_id(client_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get oauth credential by client_id {} - cause {}", client_id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_app_by_client_id(conn: &mut Connection<AuthDB>, client_id: &String) -> Result<Option<OAuthApp>, Status> {
    match OAuthApp::find_by_client_id(client_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get oauth app by client_id {} - cause {}", client_id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_user_by_email(conn: &mut Connection<AuthDB>, email: &str) -> Result<Option<User>, Status> {
    match User::find_by_email(email, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get user by email {} - cause {}", email, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn try_get_user_by_id(conn: &mut Connection<AuthDB>, id: i64) -> Result<Option<User>, Status> {
    match User::find_by_id(id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get user by id {} - cause: {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}