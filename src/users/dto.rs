use chrono::{DateTime, Utc};
use rocket::serde::{Deserialize, Serialize};
use crate::users::model::User;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserDTO {
    pub id: Option<i64>,
    pub email: String,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<Utc>>
}

impl From<User> for UserDTO {
    fn from(user: User) -> Self {
        Self {
            id: Some(user.id),
            email: user.email,
            password: None,
            last_login: user.last_login
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserUpdatePwdDTO<'r> {
    pub password: &'r str,
}
