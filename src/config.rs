use std::path::Path;
use rocket::serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Config {
    pub jwt_key: String,
    pub jwt_exp: u64,
    pub oauth_jwt_sign_key_path: String,
    pub oauth_jwt_encrypt_key: String,
    pub oauth_jwt_issuer: String,
    pub oauth_access_token_exp: u64,
    pub oauth_refresh_token_absolute_exp: u64,
    pub oauth_refresh_token_inactivity_exp: u64,
    pub oauth_auth_code_exp: u16,
    pub template_dir: String,
    pub static_dir: String
}

pub fn init_log() {
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
}
