use rocket::fairing::AdHoc;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::Database;
use rocket_dyn_templates::Template;
use crate::{auth, oauth, users, web};
use crate::config::Config;
use crate::database::{AuthDB, OAuthCodeDB, OAuthRefreshDB};

mod outcome;

#[derive(Debug)]
pub struct Prefix {
    pub prefix: String
}

#[derive(Debug)]
pub enum AuthTokenError {
    BadCount,
    Missing,
    Invalid,
    Broken
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthToken {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub jti: String,
}

pub async fn start_rocket() -> Result<(), rocket::Error> {
    let mut my_rocket = rocket::build();

    let figment = my_rocket.figment();
    let config: Config = figment.extract().expect("config");
    info!("CONFIG: {:?}", config);

    my_rocket = web::mount(my_rocket);
    my_rocket = users::mount(my_rocket);
    my_rocket = auth::mount(my_rocket);
    my_rocket = oauth::mount(my_rocket);
    let _ = my_rocket
        .attach(AdHoc::config::<Config>())
        .attach(AuthDB::init())
        .attach(OAuthCodeDB::init())
        .attach(OAuthRefreshDB::init())
        .attach(Template::fairing())
        .launch()
        .await?;
    Ok(())
}
