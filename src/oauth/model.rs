use std::collections::HashMap;
use chrono::{DateTime, Utc};
use deadpool_postgres::tokio_postgres::Row;
use postgres_types::{FromSql, ToSql};
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::serde_json;
use rocket_db_pools::Connection;
use rocket_db_pools::deadpool_redis::redis;
use rocket_db_pools::deadpool_redis::redis::RedisResult;
use tokio_postgres::Error;
use crate::database::{AuthDB, OAuthCodeDB, OAuthRefreshDB};

macro_rules! map_err {
    ($expr:expr) => {
        $expr.map_err(|e| {
            error!("{}", e);
            e
        })
    };
}

// OAuth credential model

#[derive(Debug)]
pub struct OAuthCredential {
    pub id: i64,
    pub user_id: i64,
    pub client_id: String,
    pub client_secret: String,
    pub algorithm: String,
    pub status: OAuthCredentialStatus,
    pub last_used: Option<DateTime<Utc>>,
    pub expire_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub version: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, ToSql, FromSql)]
#[postgres(name = "oauth_credential_status")]
pub enum OAuthCredentialStatus {
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
}

#[derive(Debug)]
pub struct OAuthCredentialCreateForm<'r> {
    pub user_id: i64,
    pub client_id: &'r str,
    pub client_secret: &'r str,
    pub algorithm: &'r str,
    pub status: OAuthCredentialStatus,
    pub last_used: Option<DateTime<Utc>>,
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct OAuthCredentialUpdateForm {
    pub status: OAuthCredentialStatus,
    pub expire_at: Option<DateTime<Utc>>,
}

impl OAuthCredential {
    pub async fn insert(form: &OAuthCredentialCreateForm<'_>, conn: &mut Connection<AuthDB>) -> Result<OAuthCredential, Error> {
        trace!("inserting {:?}", form);
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        INSERT INTO oauth_credentials (user_id, client_id, client_secret, algorithm, status, \
                                       last_used, expire_at, updated_at, created_at, version) \
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
        RETURNING *"
        ).await.unwrap();
        let res = (&mut *conn)
            .query_one(&stmt, &[&form.user_id, &form.client_id, &form.client_secret,
                &form.algorithm, &form.status, &form.last_used, &form.expire_at, &now,
                &now, &0])
            .await;
        map_err!(res.map(|row| row.into()))
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthCredential>, Error> {
        trace!("finding by id {}", id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE id = $1"
        ).await.unwrap();
        let res = (&mut *conn).query_opt(&stmt, &[&id]).await;
        map_err!(res.map(|opt| opt.map(|row| row.into())))
    }
    pub async fn find_by_client_id(client_id: &str, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthCredential>, Error> {
        trace!("finding by client id {}", client_id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE client_id = $1"
        ).await.unwrap();
        let res = (&mut *conn).query_opt(&stmt, &[&client_id]).await;
        map_err!(res.map(|opt| opt.map(|row| row.into())))
    }
    pub async fn find_by_user_id(user_id: i64, conn: &mut Connection<AuthDB>) -> Result<Vec<OAuthCredential>, Error> {
        trace!("finding by user id {}", user_id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE user_id = $1"
        ).await.unwrap();
        let res = (&mut *conn).query(&stmt, &[&user_id]).await;
        map_err!(res.map(|rows| rows.into_iter()
            .map(|row| row.into())
            .collect::<Vec<OAuthCredential>>()))
    }
    pub async fn update(id: i64, ver: i32, form: &OAuthCredentialUpdateForm, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("updating {} {} {:?}", id, ver, form);
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET status = $3, expire_at = $4, updated_at = $5, version = version + 1 \
        WHERE id = $1 AND version = $2"
        ).await.unwrap();
        let res = (&mut *conn).execute(&stmt, &[&id, &ver, &form.status,
            &form.expire_at, &now]).await;
        map_err!(res)
    }
    pub async fn update_status(id: i64, ver: i32, status: &OAuthCredentialStatus, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("updating status {} {} {:?}", id, ver, status);
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET status = $3, updated_at = $4 \
        WHERE id = $1 AND version = $2"
        ).await.unwrap();
        let updated_at = Utc::now();
        let res = (&mut *conn).execute(&stmt, &[&id, &ver, status,
            &updated_at]).await;
        map_err!(res)
    }
    pub async fn update_last_used(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("updating last used {}", id);
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET last_used = $2 \
        WHERE id = $1"
        ).await.unwrap();
        let res = (&mut *conn).execute(&stmt, &[&id, &now]).await;
        map_err!(res)
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("deleting {}", id);
        let stmt = (&mut *conn).prepare("\
        DELETE FROM oauth_credentials WHERE id = $1\
        ").await.unwrap();
        let res = (&mut *conn).execute(&stmt, &[&id]).await;
        map_err!(res)
    }
}

impl From<Row> for OAuthCredential {
    fn from(row: Row) -> Self {
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            client_id: row.get("client_id"),
            client_secret: row.get("client_secret"),
            algorithm: row.get("algorithm"),
            status: row.get("status"),
            last_used: row.get("last_used"),
            expire_at: row.get("expire_at"),
            updated_at: row.get("updated_at"),
            created_at: row.get("created_at"),
            version: row.get("version"),
        }
    }
}

// OAuth app model

#[derive(Debug)]
pub struct OAuthApp {
    pub id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: i64,
}

#[derive(Debug)]
pub struct OAuthAppCreateForm<'r> {
    pub client_id: &'r str,
    pub redirect_uri: &'r str,
    pub created_by: i64,
}

#[derive(Debug)]
pub struct OAuthAppUpdateForm<'r> {
    pub redirect_uri: &'r str,
}

impl OAuthApp {
    pub async fn insert(form: &OAuthAppCreateForm<'_>, conn: &mut Connection<AuthDB>) -> Result<OAuthApp, Error> {
        trace!("inserting {:?}", form);
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        INSERT INTO oauth_apps (client_id, redirect_uri, updated_at, created_at, created_by) \
        VALUES ($1, $2, $3, $4, $5) \
        RETURNING *"
        ).await.unwrap();
        let res = (&mut *conn).query_one(&stmt, &[&form.client_id,
            &form.redirect_uri, &now, &now, &form.created_by]).await;
        map_err!(res.map(|row| row.into()))
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthApp>, Error> {
        trace!("finding by id {}", id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE id = $1"
        ).await.unwrap();
        let res = (&mut *conn).query_opt(&stmt, &[&id]).await;
        map_err!(res.map(|opt| opt.map(|row| row.into())))
    }
    pub async fn find_by_client_id(client_id: &str, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthApp>, Error> {
        trace!("finding by client id {}", client_id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE client_id = $1"
        ).await.unwrap();
        let res = (&mut *conn).query_opt(&stmt, &[&client_id]).await;
        map_err!(res.map(|opt| opt.map(|row| row.into())))
    }
    pub async fn find_by_user_id(user_id: i64, conn: &mut Connection<AuthDB>) -> Result<Vec<OAuthApp>, Error> {
        trace!("finding by user id {}", user_id);
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE created_by = $1"
        ).await.unwrap();
        let res = (&mut *conn).query(&stmt, &[&user_id]).await;
        map_err!(res.map(|rows| rows.into_iter()
            .map(|row| row.into())
            .collect::<Vec<OAuthApp>>()))
    }
    pub async fn update(id: i64, form: &OAuthAppUpdateForm<'_>, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("updating {} {:?}", id, form);
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_apps \
        SET redirect_uri = $2, updated_at = $3 \
        WHERE id = $1"
        ).await.unwrap();
        let res = (&mut *conn).execute(&stmt, &[&id, &form.redirect_uri, &now]).await;
        map_err!(res)
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        trace!("deleting id {}", id);
        let stmt = (&mut *conn).prepare("\
        DELETE FROM oauth_apps WHERE id = $1"
        ).await.unwrap();
        let res = (&mut *conn).execute(&stmt, &[&id]).await;
        map_err!(res)
    }
}

impl From<Row> for OAuthApp {
    fn from(row: Row) -> Self {
        Self {
            id: row.get("id"),
            client_id: row.get("client_id"),
            redirect_uri: row.get("redirect_uri"),
            updated_at: row.get("updated_at"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
        }
    }
}

// OAuth code model

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub app_id: i64,
    pub user_id: i64,
    pub code_challenge: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCodeCreateForm<'r> {
    pub client_id: &'r str,
    pub redirect_uri: &'r str,
    pub app_id: i64,
    pub user_id: i64,
    pub code_challenge: Option<&'r str>,
}

impl OAuthCode {
    pub async fn insert(key: &str, value: &OAuthCodeCreateForm<'_>, expire: u16, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<()> {
        let json = serde_json::to_string(value).expect("can not serialize JSON for Redis");
        let res = redis::cmd("SET").arg(key).arg(json).arg("NX").arg("EX").arg(expire)
            .query_async::<_, ()>(&mut **conn).await;
        map_err!(res)
    }
    pub async fn get(key: &str, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<Option<OAuthCode>> {
        let res = redis::cmd("GET").arg(key)
            .query_async::<_, Option<String>>(&mut **conn).await
            .map(|opt| opt.map(|json| serde_json::from_str(&json)
                .expect("can not deserialize JSON from Redis")));
        map_err!(res)
    }
    pub async fn delete(key: &str, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<()> {
        let res = redis::cmd("DEL").arg(key)
            .query_async::<_, ()>(&mut **conn).await;
        map_err!(res)
    }
}

// OAuth refresh model

#[derive(Debug)]
pub struct OAuthRefresh {
    pub client_id: String,
    pub token_id: String,
    pub app_id: i64,
    pub user_id: i64,
}

impl OAuthRefresh {
    pub async fn insert(key: &str, value: &OAuthRefresh, expire: u64, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<()> {
        let res = redis::pipe()
            .atomic()
            .cmd("HSET").arg(key).arg(&[
                ("client_id", &value.client_id),
                ("token_id", &value.token_id),
                ("user_id", &value.user_id.to_string()),
                ("app_id", &value.app_id.to_string()),
            ])
            .cmd("EXPIRE").arg(key).arg(expire)
            .query_async::<_, ()>(&mut **conn).await;
        map_err!(res)
    }
    pub async fn get(key: &str, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<Option<OAuthRefresh>> {
        let res = redis::cmd("HGETALL").arg(key)
            .query_async::<_, Option<HashMap<String, String>>>(&mut **conn).await;
        map_err!(res.map(|opt| opt.map(|map| map.into())))
    }
    pub async fn delete(key: &str, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<()> {
        let res = redis::cmd("DEL").arg(key)
            .query_async::<_, ()>(&mut **conn).await;
        map_err!(res)
    }
}

impl From<HashMap<String, String>> for OAuthRefresh {
    fn from(map: HashMap<String, String>) -> Self {
        Self {
            client_id: map.get("client_id")
                .expect("expected client_id in oauth refresh").clone(),
            token_id: map.get("token_id")
                .expect("expected token_id in oauth refresh").clone(),
            app_id: map.get("app_id").map(|s| s.parse::<i64>()
                .expect("app_id in oauth refresh must be an integer"))
                .expect("expected app_id in oauth refresh"),
            user_id: map.get("user_id").map(|s| s.parse::<i64>()
                .expect("user_id in oauth refresh must be an integer"))
                .expect("expected user_id in oauth refresh"),
        }
    }
}
