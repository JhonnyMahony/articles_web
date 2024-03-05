use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct RegisterForm{
    pub email: String,
    pub password: String,
    pub confirm_password: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Typically the user's ID
    pub exp: usize,  // Expiration timestamp
}
