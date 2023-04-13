use rocket::Route;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_db_pools::Connection;
use uuid::Uuid;
use crate::database::AuthDB;
use crate::oauth::dto::{OAuthAppCreateRequestDTO, OAuthAppCreateResponseDTO, OAuthAppDTO, OAuthAppUpdateRequestDTO};
use crate::oauth::model::{OAuthApp, OAuthAppCreateForm, OAuthAppUpdateForm};
use crate::users::model::User;

pub fn get_routes() -> Vec<Route> {
    routes![get_by_user, get_by_id, create, update, delete]
}

#[post("/", data = "<dto>", format = "application/json")]
async fn create(mut conn: Connection<AuthDB>, user: User,
                dto: Json<OAuthAppCreateRequestDTO<'_>>) -> Result<Json<OAuthAppCreateResponseDTO>, Status> {
    debug!("creating oauth app {:?} for user {}", dto, user.id);
    let client_id = Uuid::new_v4().to_string();
    let form = OAuthAppCreateForm {
        client_id: &client_id,
        redirect_uri: dto.redirect_uri,
        created_by: user.id,
    };
    match OAuthApp::insert(&form, &mut conn).await {
        Ok(app) => {
            info!("oauth app created successfully with id {}", app.id);
            Ok(Json(app.into()))
        },
        Err(e) => {
            error!("can not create oauth app - cause: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/<id>")]
async fn get_by_id(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Json<OAuthAppDTO>, Status> {
    debug!("getting by id {} for user {}", id, user.id);
    secure_get_by_id(&mut conn, id, &user).await
        .map(|app| Json(app.into()))
}

#[get("/")]
async fn get_by_user(mut conn: Connection<AuthDB>, user: User) -> Result<Json<Vec<OAuthAppDTO>>, Status> {
    debug!("reading all by user: {}", user.id);
    match OAuthApp::find_by_user_id(user.id, &mut conn).await {
        Ok(app) => Ok(Json(app.into_iter()
            .map(|app| app.into())
            .collect::<Vec<OAuthAppDTO>>())),
        Err(e) => {
            error!("can not get oauth app of user {} - cause: {}", user.id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[put("/<id>", data = "<dto>", format = "application/json")]
async fn update(mut conn: Connection<AuthDB>, id: i64, user: User,
                dto: Json<OAuthAppUpdateRequestDTO<'_>>) -> Result<Status, Status> {
    debug!("updating oauth app {}", id);
    let app = secure_get_by_id(&mut conn, id, &user).await?;
    let form = OAuthAppUpdateForm {
        redirect_uri: dto.redirect_uri,
    };
    match OAuthApp::update(app.id, &form, &mut conn).await {
        Ok(n) if n > 0 => {
            info!("user {} has updated oauth app {}", user.id, app.id);
            Ok(Status::NoContent)
        },
        Ok(_) => {
            warn!("oauth app {} not found", app.id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not update oauth app {} - cause: {}", app.id, e);
            Err(Status::InternalServerError)
        }
    }
}

#[delete("/<id>")]
async fn delete(mut conn: Connection<AuthDB>, id: i64, user: User) -> Result<Status, Status> {
    debug!("deleting oauth app {}", id);
    let app = secure_get_by_id(&mut conn, id, &user).await?;
    match OAuthApp::delete(app.id, &mut conn).await {
        Ok(n) if n > 0 => {
            info!("user {} has deleted oauth app {}", user.id, app.id);
            Ok(Status::NoContent)
        },
        Ok(_) => {
            warn!("oauth app {} not found", app.id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not delete oauth app {} - cause: {}", app.id, e);
            Err(Status::InternalServerError)
        }
    }
}

async fn secure_get_by_id(conn: &mut Connection<AuthDB>, id: i64, user: &User) -> Result<OAuthApp, Status> {
    trace!("secure getById {} for user {}", id, user.id);
    let app = try_get_by_id(conn, id).await?;
    if app.created_by == user.id {
        info!("user {} is authorized to access oauth app {}", user.id, app.id);
        Ok(app)
    } else {
        warn!("user {} tried to access oauth app {} which belong to user {}", user.id, app.id, app.created_by);
        Err(Status::Forbidden)
    }
}

async fn try_get_by_id(conn: &mut Connection<AuthDB>, id: i64) -> Result<OAuthApp, Status> {
    match OAuthApp::find_by_id(id, conn).await {
        Ok(Some(app)) => Ok(app),
        Ok(None) => {
            warn!("oauth app {} not found", id);
            Err(Status::NotFound)
        },
        Err(e) => {
            error!("can not get oauth app {} - cause {}", id, e);
            Err(Status::InternalServerError)
        }
    }
}