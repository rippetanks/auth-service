use chrono::{DateTime, Utc};
use rocket::serde::{Deserialize, Serialize};
use crate::users::model::User;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UserDTO {
    pub id: i64,
    pub email: String,
    pub last_login: Option<DateTime<Utc>>
}

impl From<User> for UserDTO {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            last_login: user.last_login
        }
    }
}
