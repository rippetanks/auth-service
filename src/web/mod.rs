use std::collections::HashMap;
use std::path::{Path, PathBuf};
use rocket::{Build, State};
use rocket::fs::NamedFile;
use rocket_dyn_templates::{context, Template};
use crate::config::Config;
use crate::controller::Prefix;

#[get("/login")]
fn login(prefix: Prefix) -> Template {
    Template::render("login", context! {
        prefix: prefix.prefix,
    })
}

#[get("/oauth2/login?<params..>")]
fn oauth2_login(prefix: Prefix, params: HashMap<String, String>) -> Template {
    assert!(params.contains_key("redirect_uri"), "query param 'redirect_uri' is required");
    assert!(params.contains_key("client_id"), "query param 'client_id' is required");
    assert!(params.contains_key("response_type"), "query param 'response_type' is required");
    Template::render("oauth2", context! {
        prefix: prefix.prefix,
    })
}

#[get("/static/<file..>")]
async fn serve_static(file: PathBuf, config: &State<Config>) -> Option<NamedFile> {
    let path = Path::new(&config.static_dir).join(file);
    NamedFile::open(&path).await.ok()
}

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/web", routes![serve_static, login, oauth2_login])
}
