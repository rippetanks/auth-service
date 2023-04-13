use rocket::Build;

pub mod model;
pub mod dto;

mod apps;
mod credentials;

pub fn mount(rocket: rocket::Rocket<Build>) -> rocket::Rocket<Build> {
    rocket.mount("/oauth/credentials", credentials::get_routes())
        .mount("/oauth/apps", apps::get_routes())
}


