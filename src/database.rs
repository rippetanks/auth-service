
use rocket_contrib::databases::diesel;

#[database("db")]
pub struct AuthServiceDB(diesel::PgConnection);
