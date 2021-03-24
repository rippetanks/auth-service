
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;
#[macro_use] extern crate log;
extern crate scrypt;

use std::path::Path;

mod controller;
mod base_model;
mod database;
mod schema;

mod web;
mod users;

fn main() {
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

    let error = controller::init();
    error!("Launch failed! Error: {}", error);
}
