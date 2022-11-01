#[macro_use] extern crate rocket;
#[macro_use] extern crate log;

use crate::config::init_log;
use crate::controller::start_rocket;

mod config;
mod controller;
mod database;

mod web;
mod users;
mod auth;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    init_log();
    start_rocket().await
}
