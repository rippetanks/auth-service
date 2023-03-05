use chrono::{DateTime, Utc};
use deadpool_postgres::tokio_postgres::Row;
use postgres_types::{FromSql, ToSql};
use rocket_db_pools::Connection;
use tokio_postgres::Error;
use crate::database::AuthDB;

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
pub struct OAuthCredentialUpdateForm {
    pub status: OAuthCredentialStatus,
    pub expire_at: Option<DateTime<Utc>>,
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
