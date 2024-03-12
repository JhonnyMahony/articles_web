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
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct FogotPasswordForm{
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordForm{
    pub password: String,
    pub confirm_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Typically the user's ID
    pub exp: usize,  // Expiration timestamp
}



// Alerts
#[derive(Serialize, Deserialize)]
pub struct AlertMessage {
    level: String,
    content: String,
}

impl AlertMessage {
    pub fn new(level: &str, content: &str) -> AlertMessage {
        AlertMessage {
            level: level.to_owned(),
            content: content.to_owned(),
        }
    }
}
