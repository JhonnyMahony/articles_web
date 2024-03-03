use diesel::prelude::*;
use crate::accounts::schema::accounts;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::accounts::schema::accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Account {
    pub id: i32,
    pub email: String,
    pub password: String,
    pub created_at: bool,
}



#[derive(Insertable)]
#[diesel(table_name = accounts)]
pub struct NewAccount<'a> {
    pub email: &'a str,
    pub password: &'a str,
}
