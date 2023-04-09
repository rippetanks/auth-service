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

#[derive(Debug)]
pub struct OAuthApp {
    pub id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: i64,
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
pub struct OAuthCredentialCreateForm {
    pub user_id: i64,
    pub client_id: String,
    pub client_secret: String,
    pub algorithm: String,
    pub status: OAuthCredentialStatus,
    pub last_used: Option<DateTime<Utc>>,
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct OAuthAppCreateForm {
    pub client_id: String,
    pub redirect_uri: String,
    pub created_by: i64,
}

#[derive(Debug)]
pub struct OAuthCredentialUpdateForm {
    pub status: OAuthCredentialStatus,
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct OAuthAppUpdateForm {
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub app_id: i64,
    pub user_id: i64,
    pub code_challenge: Option<String>,
}

#[derive(Debug)]
pub struct OAuthRefresh {
    pub client_id: String,
    pub token_id: String,
    pub app_id: i64,
    pub user_id: i64,
}

impl OAuthCredential {
    pub async fn insert(form: &OAuthCredentialCreateForm, conn: &mut Connection<AuthDB>) -> Result<OAuthCredential, Error> {
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
        res.map(|row| row.into()).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthCredential>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE id = $1"
        ).await.unwrap();
        let res: Result<Option<Row>, Error> = (&mut *conn).query_opt(&stmt, &[&id]).await;
        res.map(|opt| opt.map(|row| row.into())).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn find_by_client_id(client_id: &String, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthCredential>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE client_id = $1"
        ).await.unwrap();
        let res: Result<Option<Row>, Error> = (&mut *conn).query_opt(&stmt, &[client_id]).await;
        res.map(|opt| opt.map(|row| row.into())).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn find_by_user_id(user_id: i64, conn: &mut Connection<AuthDB>) -> Result<Vec<OAuthCredential>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_credentials WHERE user_id = $1"
        ).await.unwrap();
        let res: Result<Vec<Row>, Error> = (&mut *conn).query(&stmt, &[&user_id]).await;
        res
            .map(|rows| rows.into_iter()
                .map(|row| row.into())
                .collect::<Vec<OAuthCredential>>())
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn update(id: i64, ver: i32, form: &OAuthCredentialUpdateForm, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET status = $3, expire_at = $4, updated_at = $5, version = version + 1 \
        WHERE id = $1 AND version = $2"
        ).await.unwrap();
        (&mut *conn)
            .execute(&stmt, &[&id, &ver, &form.status, &form.expire_at, &now])
            .await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn update_status(id: i64, ver: i32, status: &OAuthCredentialStatus, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET status = $3, updated_at = $4 \
        WHERE id = $1 AND version = $2"
        ).await.unwrap();
        let updated_at = Utc::now();
        (&mut *conn)
            .execute(&stmt, &[&id, &ver, status, &updated_at])
            .await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn update_last_used(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_credentials \
        SET last_used = $2 \
        WHERE id = $1"
        ).await.unwrap();
        (&mut *conn).execute(&stmt, &[&id, &now]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("DELETE FROM oauth_credentials WHERE id = $1").await.unwrap();
        (&mut *conn).execute(&stmt, &[&id]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
}

impl OAuthApp {
    pub async fn insert(form: &OAuthAppCreateForm, conn: &mut Connection<AuthDB>) -> Result<OAuthApp, Error> {
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        INSERT INTO oauth_apps (client_id, redirect_uri, updated_at, created_at, created_by) \
        VALUES ($1, $2, $3, $4, $5) \
        RETURNING *"
        ).await.unwrap();
        (&mut *conn)
            .query_one(&stmt, &[&form.client_id, &form.redirect_uri, &now, &now,
                &form.created_by]).await
            .map(|row| row.into())
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthApp>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE id = $1"
        ).await.unwrap();
        (&mut *conn).query_opt(&stmt, &[&id]).await
            .map(|opt| opt.map(|row| row.into()))
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn find_by_client_id(client_id: &String, conn: &mut Connection<AuthDB>) -> Result<Option<OAuthApp>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE client_id = $1"
        ).await.unwrap();
        (&mut *conn).query_opt(&stmt, &[client_id]).await
            .map(|opt| opt.map(|row| row.into()))
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn find_by_user_id(user_id: i64, conn: &mut Connection<AuthDB>) -> Result<Vec<OAuthApp>, Error> {
        let stmt = (&mut *conn).prepare("\
        SELECT * FROM oauth_apps WHERE created_by = $1"
        ).await.unwrap();
        (&mut *conn).query(&stmt, &[&user_id]).await
            .map(|rows| rows.into_iter()
                .map(|row| row.into())
                .collect::<Vec<OAuthApp>>())
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn update(id: i64, form: &OAuthAppUpdateForm, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let now = Utc::now();
        let stmt = (&mut *conn).prepare("\
        UPDATE oauth_apps \
        SET redirect_uri = $2, updated_at = $3 \
        WHERE id = $1"
        ).await.unwrap();
        (&mut *conn)
            .execute(&stmt, &[&id, &form.redirect_uri, &now]).await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("DELETE FROM oauth_apps WHERE id = $1").await.unwrap();
        (&mut *conn).execute(&stmt, &[&id]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
}

impl OAuthCode {
    pub async fn insert(key: &String, value: &OAuthCode, expire: u16, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<()> {
        let json = serde_json::to_string(value).expect("can not serialize JSON for Redis");
        redis::cmd("SET").arg(key).arg(json).arg("NX").arg("EX").arg(expire)
            .query_async::<_, ()>(&mut **conn).await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn get(key: &str, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<Option<OAuthCode>> {
        redis::cmd("GET").arg(key)
            .query_async::<_, Option<String>>(&mut **conn).await
            .map(|opt|
                opt.map(|json| serde_json::from_str(&json).expect("can not deserialize JSON from Redis")))
    }
    pub async fn delete(key: &str, conn: &mut Connection<OAuthCodeDB>) -> RedisResult<()> {
        redis::cmd("DEL").arg(key)
            .query_async::<_, ()>(&mut **conn).await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
}

impl OAuthRefresh {
    pub async fn insert(key: &String, value: &OAuthRefresh, expire: u64, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<()> {
        redis::pipe()
            .atomic()
            .cmd("HSET").arg(key).arg(&[
                ("client_id", value.client_id.to_string()),
                ("token_id", value.token_id.to_string()),
                ("user_id", value.user_id.to_string()),
                ("app_id", value.app_id.to_string()),
            ])
            .cmd("EXPIRE").arg(key).arg(expire)
            .query_async::<_, ()>(&mut **conn).await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn get(key: &str, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<Option<OAuthRefresh>> {
        redis::cmd("HGETALL").arg(key)
            .query_async::<_, Option<HashMap<String, String>>>(&mut **conn).await
            .map(|opt| opt.map(|map| map.into()))
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn delete(key: &str, conn: &mut Connection<OAuthRefreshDB>) -> RedisResult<()> {
        redis::cmd("DEL").arg(key)
            .query_async::<_, ()>(&mut **conn).await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
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

impl From<HashMap<String, String>> for OAuthRefresh {
    fn from(map: HashMap<String, String>) -> Self {
        Self {
            client_id: map.get("client_id").unwrap().clone(),
            token_id: map.get("token_id").unwrap().clone(),
            app_id: map.get("app_id").map(|s| s.parse::<i64>().unwrap()).unwrap(),
            user_id: map.get("user_id").map(|s| s.parse::<i64>().unwrap()).unwrap(),
        }
    }
}
