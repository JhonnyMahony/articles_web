use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterForm{
    pub email: String,
    pub password: String,
    pub confirm_password: String,
}
