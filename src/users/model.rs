use chrono::{DateTime, Utc};
use deadpool_postgres::tokio_postgres::Row;
use rocket_db_pools::Connection;
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
    pub async fn insert(form: &UserForm, conn: &mut Connection<AuthDB>) -> User {
        let stmt = (&mut *conn).prepare("\
            INSERT INTO users (email, password, algorithm, last_login) \
            VALUES ($1, $2, $3, $4) \
            RETURNING *"
        ).await.unwrap();
        let result = (&mut *conn)
            .query_one(&stmt, &[&form.email, &form.password, &form.algorithm, &form.last_login])
            .await
            .unwrap();
        (&result).into()
    }
    pub async fn find_all(conn: &mut Connection<AuthDB>) -> Vec<User> {
        let stmt = (&mut *conn).prepare("SELECT * FROM users").await.unwrap();
        let rows = (&mut *conn).query(&stmt, &[]).await.unwrap();
        rows.iter().map(|row| row.into()).collect::<Vec<User>>()
    }
    pub async fn find_by_id(id: i64, conn: &mut Connection<AuthDB>) -> User {
        let stmt = (&mut *conn).prepare("SELECT * FROM users WHERE id = $1").await.unwrap();
        let row = (&mut *conn).query_one(&stmt, &[&id]).await.unwrap();
        (&row).into()
    }
    pub async fn read_by_email(email: &str, conn: &mut Connection<AuthDB>) -> User {
        let stmt = (&mut *conn).prepare("SELECT * FROM users WHERE email = $1").await.unwrap();
        let row = (&mut *conn).query_one(&stmt, &[&email]).await.unwrap();
        (&row).into()
    }
    pub async fn update(id: i64, form: &UserForm, conn: &mut Connection<AuthDB>) -> u64 {
        let stmt = (&mut *conn).prepare("\
            UPDATE users \
            SET email = $2, password = $3, algorithm = $4, last_login = $5 \
            WHERE id = $1\
        ").await.unwrap();
        (&mut *conn)
            .execute(&stmt, &[&id, &form.email, &form.password, &form.algorithm, &form.last_login])
            .await
            .unwrap()
    }
    pub async fn update_last_login(id: i64, conn: &mut Connection<AuthDB>) -> u64 {
        let stmt = (&mut *conn).prepare("UPDATE users SET last_login = $2 WHERE id = $1").await.unwrap();
        let last_login = Utc::now();
        (&mut *conn)
            .execute(&stmt, &[&id, &last_login])
            .await
            .unwrap()
    }
    pub async fn delete(id: i64, conn: &mut Connection<AuthDB>) -> u64 {
        let stmt = (&mut *conn).prepare("DELETE FROM users WHERE id = $1").await.unwrap();
        (&mut *conn).execute(&stmt, &[&id]).await.unwrap()
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
