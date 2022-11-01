use std::path::{Path, PathBuf};
use rocket::{Build, State};
use rocket::fs::NamedFile;
use rocket_dyn_templates::{context, Template};
use crate::config::Config;
use crate::controller::Prefix;

#[get("/login")]
fn login(prefix: Prefix) -> Template {
    Template::render("login", context! {
        prefix: prefix.prefix
    })
}

#[get("/static/<file..>")]
async fn serve_static(file: PathBuf, config: &State<Config>) -> Option<NamedFile> {
    let path = Path::new(&config.static_dir).join(file);
    NamedFile::open(&path).await.ok()
}

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/web", routes![serve_static, login])
}
