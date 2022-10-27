#[macro_use] extern crate rocket;
//#[macro_use] extern crate diesel;
#[macro_use] extern crate log;
//extern crate scrypt;

use std::path::Path;
use rocket::fairing::AdHoc;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::State;
use rocket_db_pools::{Connection, Database};
use uuid::Uuid;
use crate::database::AuthDB;
use crate::users::dto::UserDTO;
use crate::users::model::{User, UserForm};

//mod controller;
//mod base_model;
mod database;

//mod web;
mod users;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    pub jwt_key: String,
    pub jwt_exp: i32,
    pub template_dir: String,
    pub static_dir: String
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let path = if cfg!(windows) {
        "log-config.yml"
    } else {
        let path = "/etc/auth-service/log-config.yml";
        if Path::new(path).exists() {
            path
        } else {
            "log-config.yml"
        }
    };
    log4rs::init_file(path, Default::default()).unwrap();

    let my_rocket = rocket::build();

    let figment = my_rocket.figment();
    let config: Config = figment.extract().expect("config");
    info!("CONFIG: {:?}", config);

    let _ = my_rocket.mount("/test", routes!(test))
        .attach(AdHoc::config::<Config>())
        .attach(AuthDB::init())
        .launch()
        .await?;
    Ok(())
}

#[get("/")]
async fn test(config: &State<Config>, mut conn: Connection<AuthDB>) -> Json<UserDTO> {
    info!("CONFIG: {:?}", config);

    info!("TEST DB: {:?}", User::find_all(&mut conn).await);
    info!("TEST DB: {:?}", User::find_by_id(1, &mut conn).await);

    let form = UserForm {
        email: Uuid::new_v4().to_string(),
        password: "".to_string(),
        algorithm: "".to_string(),
        last_login: None
    };
    info!("INSERT: {:?}", User::insert(&form, &mut conn).await);

    Json(User::find_by_id(1, &mut conn).await.into())
}
