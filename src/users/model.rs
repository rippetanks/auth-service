use chrono::{DateTime, Utc};
use deadpool_postgres::tokio_postgres::Row;
use rocket_db_pools::Connection;
use tokio_postgres::Error;
use crate::database::AuthDB;

#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub algorithm: String,
    pub last_login: Option<DateTime<Utc>>
}

#[derive(Debug)]
pub struct UserForm {
    pub email: String,
    pub password: String,
    pub algorithm: String,
    pub last_login: Option<DateTime<Utc>>
}

impl User {
    pub async fn insert(form: &UserForm, conn: &mut Connection<AuthDB>) -> Result<User, Error> {
        let stmt = (&mut *conn).prepare("\
            INSERT INTO users (email, password, algorithm, last_login) \
            VALUES ($1, $2, $3, $4) \
            RETURNING *"
        ).await.unwrap();
        let res = (&mut *conn)
            .query_one(&stmt, &[&form.email, &form.password, &form.algorithm, &form.last_login])
            .await;
        res.map(|row| (&row).into()).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    #[allow(dead_code)]
    pub async fn find_all(conn: &mut Connection<AuthDB>) -> Result<Vec<User>, Error> {
        let stmt = (&mut *conn).prepare("SELECT * FROM users").await.unwrap();
        let res: Result<Vec<Row>, Error> = (&mut *conn).query(&stmt, &[]).await;
        res
            .map(|rows| rows.iter()
                .map(|row| row.into())
                .collect::<Vec<User>>())
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> Result<Option<User>, Error> {
        let stmt = (&mut *conn).prepare("SELECT * FROM users WHERE id = $1").await.unwrap();
        let res: Result<Option<Row>, Error> = (&mut *conn).query_opt(&stmt, &[&id]).await;
        res.map(|opt| opt.map(|row| (&row).into())).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn find_by_email(email: &str, conn: &mut Connection<AuthDB>) -> Result<Option<User>, Error> {
        let stmt = (&mut *conn).prepare("SELECT * FROM users WHERE email = $1").await.unwrap();
        let res: Result<Option<Row>, Error> = (&mut *conn).query_opt(&stmt, &[&email]).await;
        res.map(|opt| opt.map(|row| (&row).into())).map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn update(id: i64, form: &UserForm, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("UPDATE users SET email = $2 WHERE id = $1").await.unwrap();
        (&mut *conn).execute(&stmt, &[&id, &form.email]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn update_password(id: i64, form: &UserForm, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("UPDATE users SET password = $2, algorithm = $3 WHERE id = $1").await.unwrap();
        (&mut *conn)
            .execute(&stmt, &[&id, &form.password, &form.algorithm])
            .await
            .map_err(|e| {
                warn!("{}", e);
                e
            })
    }
    pub async fn update_last_login(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("UPDATE users SET last_login = $2 WHERE id = $1").await.unwrap();
        let last_login = Utc::now();
        (&mut *conn).execute(&stmt, &[&id, &last_login]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> Result<u64, Error> {
        let stmt = (&mut *conn).prepare("DELETE FROM users WHERE id = $1").await.unwrap();
        (&mut *conn).execute(&stmt, &[&id]).await.map_err(|e| {
            warn!("{}", e);
            e
        })
    }
}

impl From<&Row> for User {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            email: row.get("email"),
            password: row.get("password"),
            algorithm: row.get("algorithm"),
            last_login: row.get("last_login")
        }
    }
}
