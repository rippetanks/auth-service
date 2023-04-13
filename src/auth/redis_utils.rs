use rocket::http::Status;
use rocket::State;
use rocket_db_pools::Connection;
use crate::auth::token::OAuthRefreshToken;
use crate::config::Config;
use crate::database::{OAuthCodeDB, OAuthRefreshDB};
use crate::oauth::model::{OAuthCode, OAuthCodeCreateForm, OAuthRefresh};

pub async fn put_auth_code_to_redis(conn: &mut Connection<OAuthCodeDB>,
                                    code: &String,
                                    payload: &OAuthCodeCreateForm<'_>,
                                    config: &State<Config>) -> Result<(), Status> {
    match OAuthCode::insert(code, payload, config.oauth_auth_code_exp, conn).await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("can not add authorization code to Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn get_auth_code_from_redis(conn: &mut Connection<OAuthCodeDB>, code: &str) -> Result<OAuthCode, Status> {
    match OAuthCode::get(code, conn).await {
        Ok(Some(code)) => Ok(code),
        Ok(None) => {
            warn!("Auth code {} not found!", code);
            Err(Status::Unauthorized)
        },
        Err(e) => {
            error!("can not get authorization code from Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn remove_auth_code_from_redis(conn: &mut Connection<OAuthCodeDB>, code: &str) -> Result<(), Status> {
    match OAuthCode::delete(code, conn).await {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("can not remove authorization code from Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn put_refresh_token_to_redis(conn: &mut Connection<OAuthRefreshDB>,
                                        token: &OAuthRefreshToken,
                                        config: &State<Config>,) -> Result<(), Status> {
    let payload = OAuthRefresh {
        client_id: token.client_id.clone(),
        token_id: token.jti.clone(),
        user_id: token.user_id,
        app_id: token.app_id,
    };
    match OAuthRefresh::insert(&token.correlation_id, &payload, config.oauth_refresh_token_inactivity_exp, conn).await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("can not add refresh token to Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn get_refresh_token_from_redis(conn: &mut Connection<OAuthRefreshDB>,
                                          token: &OAuthRefreshToken) -> Result<Option<OAuthRefresh>, Status> {
    match OAuthRefresh::get(&token.correlation_id, conn).await {
        Ok(opt) => Ok(opt),
        Err(e) => {
            error!("can not get refresh token from Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

pub async fn remove_refresh_token_from_redis(conn: &mut Connection<OAuthRefreshDB>,
                                             token_id: &str) -> Result<(), Status> {
    match OAuthRefresh::delete(token_id, conn).await {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("can not delete refresh token from Redis - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}