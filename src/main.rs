#[macro_use] extern crate rocket;
//#[macro_use] extern crate diesel;
#[macro_use] extern crate log;
//extern crate scrypt;

use std::path::Path;
use rocket::fairing::AdHoc;
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

//mod controller;
//mod base_model;
//mod database;
//mod schema;

//mod web;
//mod users;

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

    let _rocket = rocket::build();
    let figment = _rocket.figment();

    let config: Config = figment.extract().expect("config");
    info!("CONFIG: {:?}", config);

    let _ = _rocket.mount("/test", routes!(test))
        .attach(AdHoc::config::<Config>())
        .launch()
        .await?;
    Ok(())
}

#[get("/")]
async fn test(config: &State<Config>) -> &'static str {
    info!("CONFIG: {:?}", config);
    "Test"
}
