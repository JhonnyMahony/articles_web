use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::accounts::schema::accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Account {
    pub id: i32,
    pub email: String,
    pub password: String,
    pub created_at: NaiveDateTime,
    pub is_verified: bool,
}

#[derive(Insertable)]
#[diesel(table_name = crate::accounts::schema::accounts)]
pub struct NewAccount<'a> {
    pub email: &'a str,
    pub password: &'a str,
}

#[derive(Queryable, Selectable, AsChangeset)]
#[diesel(table_name = crate::accounts::schema::user_profiles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserProfile {
    pub id: i32,
    pub account_id: i32,
    pub name: String,
    pub surname: String,
    pub photo: String,
    pub phone_number: String,
}

#[derive(Insertable)]
#[diesel(table_name = crate::accounts::schema::user_profiles)]
pub struct NewUserProfile<'a> {
    pub account_id: i32,
    pub name: &'a str,
    pub surname: &'a str,
    pub photo: Option<&'a str>,
    pub phone_number: &'a str,
}

