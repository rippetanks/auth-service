use rocket_db_pools::{deadpool_postgres, Database};

#[derive(Database)]
#[database("auth_db")]
pub struct AuthDB(deadpool_postgres::Pool);
