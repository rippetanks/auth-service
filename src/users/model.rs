
use diesel;
use diesel::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::database::AuthServiceDB;
use crate::schema::users;

#[table_name = "users"]
#[derive(Debug,Serialize,Deserialize,Queryable,Identifiable,Associations)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub algorithm: String,
    pub last_login: Option<DateTime<Utc>>
}

#[table_name = "users"]
#[derive(Debug,Insertable,AsChangeset)]
pub struct UserForm {
    pub email: String,
    pub password: String,
    pub algorithm: String,
    pub last_login: Option<DateTime<Utc>>
}

impl User {
    pub fn create(form: &UserForm, conn: &AuthServiceDB) -> QueryResult<User> {
        diesel::insert_into(users::table)
            .values(form)
            .get_result::<User>(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn read(conn: &AuthServiceDB) -> QueryResult<Vec<User>> {
        users::table.load::<User>(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn read_by_id(id: i64, conn: &AuthServiceDB) -> QueryResult<User> {
        users::table.find(id).first::<User>(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn read_by_email(email: &str, conn: &AuthServiceDB) -> QueryResult<User> {
        users::table.filter(users::email.eq(email))
            .first(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn update(id: i64, form: &UserForm, conn: &AuthServiceDB) -> QueryResult<usize> {
        diesel::update(users::table.find(id))
            .set(form)
            .execute(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn update_last_login(id: i64, conn: &AuthServiceDB) -> QueryResult<usize> {
        diesel::update(users::table.find(id))
            .set(users::last_login.eq(Utc::now()))
            .execute(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    pub fn delete(id: i64, conn: &AuthServiceDB) -> QueryResult<usize> {
        diesel::delete(users::table.find(id))
            .execute(&*(*conn))
            .map_err(|e| { warn!("{}", e); e })
    }
    ///
    /// Not all info can be returned.
    pub fn mask(user: &mut User) {
        user.password = String::new();
        user.algorithm = String::new();
    }
}
