//use rocket::Build;
//use std::collections::HashMap;
//use rocket_dyn_templates::Template;

//use crate::controller::{Prefix};

/*#[get("/login")]
fn login(prefix: Prefix) -> Template {
    let mut context: HashMap<String, String> = HashMap::new();
    context.insert("prefix".to_string(), prefix.prefix);
    Template::render("login", &context)
}*/

/* FIXME
#[get("/static/<file..>")]
fn serve_static(file: PathBuf, extras: State<Extras>) -> Result<NamedFile, NotFound<String>> {
    let path = Path::new(&extras.static_dir).join(file);
    NamedFile::open(&path).map_err(|_| NotFound(format!("Bad path: {:?}", path)))
}
 */

/*pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/web", routes![/* FIXME serve_static, */ login])
}*/
