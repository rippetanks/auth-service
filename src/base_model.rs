
use rocket_contrib::json::Json;
use rocket::http::Status;
use rocket::response::status::Custom;
use diesel::result::Error;

use crate::users::model::User;

pub trait BaseModel<T> {
    fn unpack(result: Result<Vec<T>, Error>) -> Result<Json<Vec<T>>, Custom<String>> {
        match result {
            Ok(result) if result.is_empty() => {
                debug!("unpack no content");
                Err(Custom(Status::NoContent, String::new()))
            },
            Ok(result) => Ok(Json(result)),
            Err(e) => {
                error!("Can not unpack! Cause {}", e);
                Err(Custom(Status::InternalServerError, e.to_string()))
            }
        }
    }
}

impl BaseModel<User> for User { }
