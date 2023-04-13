use rocket_db_pools::{deadpool_postgres, deadpool_redis, Database};

#[derive(Database)]
#[database("auth_db")]
pub struct AuthDB(deadpool_postgres::Pool);

#[derive(Database)]
#[database("oauth_code_db")]
pub struct OAuthCodeDB(deadpool_redis::Pool);

#[derive(Database)]
#[database("oauth_refresh_db")]
pub struct OAuthRefreshDB(deadpool_redis::Pool);
