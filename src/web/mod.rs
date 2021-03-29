
use rocket_contrib::templates::Template;
use std::path::{Path, PathBuf};
use rocket::response::NamedFile;
use rocket::response::status::NotFound;
use rocket::State;
use std::collections::HashMap;

use crate::controller::{Extras, Prefix};

#[get("/login")]
fn login(prefix: Prefix) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("prefix".to_string(), prefix.prefix);
    Template::render("login", &context)
}

#[get("/static/<file..>")]
fn serve_static(file: PathBuf, extras: State<Extras>) -> Result<NamedFile, NotFound<String>> {
    let path = Path::new(&extras.static_dir).join(file);
    NamedFile::open(&path).map_err(|_| NotFound(format!("Bad path: {:?}", path)))
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    rocket.mount("/web", routes![serve_static, login])
}
