use rocket::http::Status;
use url::Url;

pub fn parse_uri(uri: &str) -> Result<Url, Status> {
    Url::parse(uri).map_err(|e| {
        warn!("redirect_uri {} is not formatted correctly - cause {}", uri, e);
        Status::BadRequest
    })
}