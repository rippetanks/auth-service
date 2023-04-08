use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use rocket::{Build, State};
use rocket::form::Form;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::serde::json::serde_json::json;
use rocket_db_pools::Connection;
use url::Url;
use uuid::Uuid;
use crate::auth::crypto::generate_secure_code;
use crate::auth::db_utils::{get_app_by_client_id, get_by_client_id, get_user_by_email, get_user_by_id};
use crate::auth::http_basic_auth::HttpBasicAuth;
use crate::auth::redis_utils::{get_auth_code_from_redis, get_refresh_token_from_redis, put_auth_code_to_redis, put_refresh_token_to_redis, remove_auth_code_from_redis, remove_refresh_token_from_redis};
use crate::auth::token_utils::{create_oauth2_access_token, create_oauth2_refresh_token, read_oauth2_refresh_token};
use crate::auth::utils::parse_uri;
use crate::config::Config;
use crate::controller::AuthToken;
use crate::database::{AuthDB, OAuthCodeDB, OAuthRefreshDB};
use crate::oauth::model::{OAuthCode, OAuthCredential};
use crate::users::model::User;

pub mod crypto;
pub mod token_utils;

mod http_basic_auth;
mod utils;
mod db_utils;
mod redis_utils;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AuthJSON<'r> {
    email: &'r str,
    password: &'r str,
}

#[derive(Debug, FromForm)]
struct OAuth2TokenRequest<'r> {
    grant_type: &'r str,
    code: Option<&'r str>,
    redirect_uri: Option<&'r str>,
    refresh_token: Option<&'r str>,
    scope: Option<&'r str>,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
struct OAuth2TokenResponse {
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
#[serde(crate = "rocket::serde")]
struct OAuth2LoginResponse {
    code: String,
}

#[derive(Debug)]
struct OAuth2AuthFlowBody<'r> {
    code: &'r str,
    redirect_uri: &'r str,
}

#[derive(Debug)]
struct OAuth2RefreshFlowBody<'r> {
    refresh_token: &'r str,
}

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/auth", routes![login, oauth2_token, oauth2_authorize, oauth2_login])
}

#[post("/login", data = "<json>", format = "application/json")]
async fn login(mut conn: Connection<AuthDB>, config: &State<Config>, json: Json<AuthJSON<'_>>) -> Result<String, Status> {
    let user = handle_login(json.email, json.password, &mut conn).await?;
    let token = generate_jwt_token(&user, &config)?;
    if User::update_last_login(user.id, &mut conn).await.is_err() {
        error!("can not update last login of user {}", user.id);
    }
    Ok(json!({"token": token}).to_string())
}

#[get("/oauth2/authorize?<response_type>&<client_id>&<redirect_uri>&<scope>&<state>")]
async fn oauth2_authorize(mut conn: Connection<AuthDB>,
                          response_type: &str, client_id: &str, redirect_uri: Option<&str>,
                          scope: Option<&str>, state: Option<&str>) -> Result<Redirect, Status> {
    info!("oauth2 authorize params - response_type: {}, client_id: {}, redirect_uri: {:?}, scope: {:?}",
        response_type, client_id, redirect_uri, scope);
    if response_type != "code" {
        warn!("response_type {} is invalid", response_type);
        return Err(Status::BadRequest);
    }
    let app = get_app_by_client_id(&mut conn, &client_id.to_string()).await?;
    let app_redirect_uri = parse_uri(&app.redirect_uri)?;
    let redirect_to = redirect_uri
        .map(|u| parse_uri(u))
        .unwrap_or(Ok(app_redirect_uri.clone()))?;
    if redirect_uri.is_some() && !validate_redirect_uri(&redirect_to, &app_redirect_uri) {
        warn!("redirect_uri {} is invalid", redirect_to);
        return Err(Status::BadRequest);
    }
    let params = to_query_params(client_id, &redirect_to, scope, state);
    let uri = format!("{}?{}", "/web/oauth2/login", params);
    info!("redirecting to {}", uri);
    Ok(Redirect::found(uri))
}

#[post("/oauth2/login?<client_id>&<redirect_uri>", data = "<json>", format = "application/json")]
async fn oauth2_login(mut conn_auth: Connection<AuthDB>, mut conn_token: Connection<OAuthCodeDB>,
                      config: &State<Config>, client_id: &str, redirect_uri: &str,
                      json: Json<AuthJSON<'_>>) -> Result<Json<OAuth2LoginResponse>, Status> {
    let app = get_app_by_client_id(&mut conn_auth, &client_id.to_string()).await?;
    let user = handle_login(json.email, json.password, &mut conn_auth).await?;
    if app.created_by != user.id {
        warn!("user {} tried to use app with client_id {} of user {}", user.id, client_id, app.created_by);
        return Err(Status::Forbidden);
    }
    let code = generate_secure_code();
    let oauth_code = OAuthCode {
        redirect_uri: redirect_uri.to_string(),
        client_id: client_id.to_string(),
        app_id: app.id,
        user_id: user.id,
    };
    put_auth_code_to_redis(&mut conn_token, &code, &oauth_code, config).await?;
    if User::update_last_login(user.id, &mut conn_auth).await.is_err() {
        error!("can not update last login of user {}", user.id);
    }
    Ok(Json(OAuth2LoginResponse {
        code,
    }))
}

#[post("/oauth2/token", data = "<body>")]
async fn oauth2_token(mut conn_auth: Connection<AuthDB>,
                      mut conn_code: Connection<OAuthCodeDB>,
                      mut conn_refresh: Connection<OAuthRefreshDB>,
                      config: &State<Config>, body: Form<OAuth2TokenRequest<'_>>,
                      auth_header: Option<HttpBasicAuth>) -> Result<Json<OAuth2TokenResponse>, Status> {
    info!("{:?} {:?}", body, auth_header);
    match body.grant_type {
        "client_credentials" if auth_header.is_some() => {
            let auth = auth_header.unwrap();
            let credential = get_by_client_id(&mut conn_auth, &auth.client_id).await?;
            if crypto::hash_secret_check(&auth.client_secret, &credential.client_secret) {
                let (token, _) = create_oauth2_access_token(&(&credential).into(), &config)?;
                if OAuthCredential::update_last_used(credential.id, &mut conn_auth).await.is_err() {
                    error!("can not update last used of oauth credential {}", credential.id);
                }
                Ok(Json(OAuth2TokenResponse {
                    access_token: token,
                    token_type: "bearer".to_string(),
                    expires_in: config.oauth_access_token_exp,
                    refresh_token: None,
                }))
            } else {
                warn!("Access denied! Wrong oauth credential for client_id {}", auth.client_id);
                Err(Status::Unauthorized)
            }
        },
        "client_credentials" => {
            warn!("Access denied! Missing authentication header");
            Err(Status::Unauthorized)
        }
        "authorization_code" => {
            let ac_body = body_for_auth_flow(&body)?;
            debug!("body: {:?}", ac_body);
            let redis_code = get_auth_code_from_redis(&mut conn_code, ac_body.code).await?;
            remove_auth_code_from_redis(&mut conn_code, ac_body.code).await?;
            if ac_body.redirect_uri != redis_code.redirect_uri {
                warn!("Access denied! Redirect URI is not the same.");
                return Err(Status::Unauthorized);
            }
            let (a_token, _) = create_oauth2_access_token(&(&redis_code).into(), config)?;
            let (r_token, r_info) = create_oauth2_refresh_token(Some(&redis_code), None, config)?;
            put_refresh_token_to_redis(&mut conn_refresh, &r_info, &config).await?;
            Ok(Json(OAuth2TokenResponse {
                access_token: a_token,
                token_type: "bearer".to_string(),
                expires_in: config.oauth_access_token_exp,
                refresh_token: Some(r_token),
            }))
        },
        "refresh_token" => {
            let rt_body = body_for_refresh_flow(&body)?;
            debug!("body: {:?}", rt_body);
            let parsed_token = read_oauth2_refresh_token(rt_body.refresh_token, &config.oauth_jwt_encrypt_key)?;
            debug!("parsed token: {:?}", parsed_token);
            let redis_token = match get_refresh_token_from_redis(&mut conn_refresh, &parsed_token).await? {
                Some(t) if t.token_id == parsed_token.jti => Ok(t),
                Some(_) => {
                    warn!("detected reuse of refresh token {}", parsed_token.correlation_id);
                    remove_refresh_token_from_redis(&mut conn_refresh, &parsed_token.correlation_id).await?;
                    Err(Status::Unauthorized)
                },
                None => {
                    warn!("refresh token {} not found on Redis", parsed_token.correlation_id);
                    Err(Status::Unauthorized)
                }
            }?;
            debug!("redis token: {:?}", redis_token);
            get_app_by_client_id(&mut conn_auth, &parsed_token.client_id).await?;
            get_user_by_id(&mut conn_auth, parsed_token.user_id).await?;
            let (a_token, _) = create_oauth2_access_token(&(&parsed_token).into(), config)?;
            let (r_token, r_info) = create_oauth2_refresh_token(None, Some(&parsed_token), config)?;
            put_refresh_token_to_redis(&mut conn_refresh, &r_info, &config).await?;
            Ok(Json(OAuth2TokenResponse {
                access_token: a_token,
                token_type: "bearer".to_string(),
                expires_in: config.oauth_access_token_exp,
                refresh_token: Some(r_token),
            }))
        },
        _ => {
            warn!("grant type {} not supported", body.grant_type);
            Err(Status::BadRequest)
        }
    }
}

async fn handle_login(email: &str, password: &str, conn: &mut Connection<AuthDB>) -> Result<User, Status> {
    let user = get_user_by_email(conn, email).await?;
    if crypto::hash_pwd_check(password, user.password.as_str()) {
        Ok(user)
    } else {
        warn!("Access denied! Wrong password for user {}", email);
        Err(Status::Unauthorized)
    }
}

fn generate_jwt_token(user: &User, config: &State<Config>) -> Result<String, Status> {
    let header = Header::new(Algorithm::HS512);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = AuthToken {
        sub: user.id,
        exp: (now + config.jwt_exp) as usize,
        iat: now as usize,
        iss: "".to_string(),
        jti: Uuid::new_v4().to_string(),
    };
    let encoding_key = EncodingKey::from_secret(config.jwt_key.as_ref());
    match encode(&header, &claims, &encoding_key) {
        Ok(token) => Ok(token),
        Err(e) => {
            error!("can not encode JWT token - cause {}", e);
            Err(Status::InternalServerError)
        }
    }
}

fn validate_redirect_uri(redirect_uri: &Url, registered_uri: &Url) -> bool {
    redirect_uri.scheme() == redirect_uri.scheme()
        && redirect_uri.host_str() == registered_uri.host_str()
        && redirect_uri.port() == registered_uri.port()
        && redirect_uri.path() == registered_uri.path()
}

fn body_for_auth_flow<'r>(form: &OAuth2TokenRequest<'r>) -> Result<OAuth2AuthFlowBody<'r>, Status> {
    if form.code.is_none() || form.redirect_uri.is_none() {
        warn!("missing required field in form");
        return Err(Status::BadRequest);
    }
    Ok(OAuth2AuthFlowBody {
        code: form.code.unwrap(),
        redirect_uri: form.redirect_uri.unwrap(),
    })
}

fn body_for_refresh_flow<'r>(form: &OAuth2TokenRequest<'r>) -> Result<OAuth2RefreshFlowBody<'r>, Status> {
    if form.refresh_token.is_none() {
        warn!("missing required field in form");
        return Err(Status::BadRequest);
    }
    Ok(OAuth2RefreshFlowBody {
        refresh_token: form.refresh_token.unwrap(),
    })
}

fn to_query_params(client_id: &str, redirect_to: &Url, scope: Option<&str>, state: Option<&str>) -> String {
    let mut params = Vec::new();
    params.push(("response_type", "code"));
    params.push(("client_id", client_id));
    params.push(("redirect_uri", redirect_to.as_str()));
    scope.map(|s| params.push(("scope", s)));
    state.map(|s| params.push(("state", s)));
    querystring::stringify(params)
}