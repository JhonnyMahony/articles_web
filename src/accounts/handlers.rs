use crate::accounts::forms::{AlertMessage, Claims, LoginForm, RegisterForm, FogotPasswordForm, ResetPasswordForm};
use crate::accounts::schema::user_profiles;
use actix_session::Session;
use actix_web::{http, web, HttpResponse, Responder};
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use tera::{Context, Tera};
// diesel
use crate::accounts::models::{Account, NewAccount, NewUserProfile, UserProfile};
use crate::establish_connection;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::prelude::*;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{message::Mailbox, Message, SmtpTransport, Transport};
use uuid::Uuid;
// Assuming `Model` is the correct entity from your `models.rs`
use actix_multipart::Multipart;
use futures::{StreamExt, TryStreamExt};
use sanitize_filename;
use std::io::Write;
use validator::validate_email;

async fn alert_message(
    session: Session,
    location: &str,
    level: &str,
    content: &str,
) -> HttpResponse {
    let alert_message = AlertMessage::new(level, content);
    let _ = session.insert("alert_message", alert_message);
    return HttpResponse::Found()
        .append_header((http::header::LOCATION, location))
        .finish();
}

fn account_exists(connection: &mut PgConnection, account_email: &str) -> bool {
    use crate::accounts::schema::accounts::dsl::*;
    match accounts
        .filter(email.eq(account_email))
        .first::<Account>(connection)
    {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub async fn verify_account(token: web::Path<String>) -> impl Responder {
    let connection = &mut establish_connection();
    let token = token.into_inner();
    let secret = "verification"; // Use the same secret as when encoding
    use crate::accounts::schema::accounts::dsl::*;
    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::ExpiredSignature => {
                let mut validation = Validation::default();
                validation.validate_exp = false; // Disable expiration validation
                if let Ok(token_data) = decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &validation,
                ) {
                    let user_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");

                    // Assuming you have a function `get_user_email` to fetch the user's email from the database
                    if let Ok(user_email) = get_user_email(user_id).await {
                        // Resend the verification email
                        if let Err(e) = send_verification_email(&user_email, &user_id.to_string(), "http://127.0.0.1:8000/verify") {
                            println!("Failed to resend verification email: {:?}", e);
                            return HttpResponse::InternalServerError()
                                .body("Failed to resend verification email");
                        }
                    }
                    return HttpResponse::Ok().body(
                        "Verification link has expired. A new verification email has been sent.",
                    );
                } else {
                    return HttpResponse::Unauthorized().body("Invalid token");
                }
            }
            _ => return HttpResponse::Unauthorized().body("Invalid token"),
        },
    };

    let account_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");
    let _ = diesel::update(accounts.find(account_id))
        .set(is_verified.eq(true))
        .execute(&mut *connection);

    HttpResponse::Ok().body("Account verified")
}

fn send_verification_email(email: &str, user_id: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration as usize,
    };
    let secret = "verification";
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )?;
    let email = Message::builder()
        .from("gradprus.manager@gmail.com".parse::<Mailbox>()?)
        .to(email.parse::<Mailbox>()?)
        .subject("Verify your account")
        .body(format!(
            "Please click on the link to verify your account: {}/{}",url,token
        ))?;

    let creds = Credentials::new(
        "gradprus.manager@gmail.com".into(),
        "hzxijrovvyvjgciu".into(),
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

async fn submit_form(session: &Session, csrf_token: &str) -> bool {
    let form_csrf_token = csrf_token;
    let session_csrf_token: Option<String> = session.get("csrf_token").expect("wrong csrf");

    match session_csrf_token {
        Some(token) if token == form_csrf_token => true,
        _ => false,
    }
}

pub async fn login_post(session: Session, form: web::Form<LoginForm>) -> impl Responder {
    use crate::accounts::schema::accounts::dsl::*;
    let connection = &mut establish_connection();

    let is_form_valid = submit_form(&session, &form.csrf_token).await;
    if !is_form_valid {
        let alert_message = AlertMessage::new("error", "Csrf token uncorrect");
        let _ = session.insert("alert_message", alert_message);
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/login"))
            .finish();
    }
    let results = accounts
        .filter(email.eq(&form.email))
        .limit(5)
        .select(Account::as_select())
        .load(connection)
        .expect("Error loading posts");

    if results.is_empty() {
        let alert_message = AlertMessage::new("error", "Account doesnt exist");
        let _ = session.insert("alert_message", alert_message);
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/login"))
            .finish();
    }
    let user_id = &results[0].id;
    let is_verifyde = &results[0].is_verified;
    println!("{}", is_verifyde);
    if let Err(e) = session.insert("account_id", &user_id) {
        // Handle the error, e.g., by logging or returning an error response
        println!("Failed to insert user_id into session: {:?}", e);
    }
    println!("{}",&user_id);
    match verify(&form.password, &results[0].password) {
        Ok(is_password_correct) => {
            if is_password_correct {
                return HttpResponse::Found()
                    .append_header((http::header::LOCATION, "/dashboard"))
                    .finish();
            } else {
                let alert_message = AlertMessage::new("error", "incorrect password or email");
                let _ = session.insert("alert_message", alert_message);
                return HttpResponse::Found()
                    .append_header((http::header::LOCATION, "/login"))
                    .finish();
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .body("An error occurred during password verification");
        }
    }
}

pub async fn login_get(session: Session, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    if let Some(alert_message) = session.get::<AlertMessage>("alert_message").unwrap() {
        context.insert("alert_message", &alert_message);
        session.remove("alert_message");
    }
    let csrf_token = Uuid::new_v4().to_string();
    let _ = session.insert("csrf_token", &csrf_token);

    context.insert("title", "you on login page");
    context.insert("csrf_token", &csrf_token);

    let rendered = tera.render("accounts/login.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub async fn register_get(session: Session, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    if let Some(alert_message) = session.get::<AlertMessage>("alert_message").unwrap() {
        context.insert("alert_message", &alert_message);
        session.remove("alert_message");
    }
    let csrf_token = Uuid::new_v4().to_string();
    let _ = session.insert("csrf_token", &csrf_token);
    context.insert("csrf_token", &csrf_token);
    context.insert("title", "you on regoster page");
    let rendered = tera.render("accounts/register.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub async fn register_post(session: Session, form: web::Form<RegisterForm>) -> impl Responder {
    // Database conection
    let connection = &mut establish_connection();
    // Csrf validation
    let is_form_valid = submit_form(&session, &form.csrf_token).await;
    if !is_form_valid {
        return alert_message(session, "/register", "error", "Invalid csrf token").await;
    }
    // Form validation
    if !validate_email(&form.email) {
        return alert_message(session, "/register", "error", "Invalid format of  email").await;
    } else if account_exists(connection, &form.email) {
        return alert_message(session, "/register", "error", "Account exist").await;
    } else if form.password.to_lowercase() == form.password {
        return alert_message(
            session,
            "/register",
            "error",
            "password need at least 1 upper case letter",
        )
        .await;
    } else if form.password.len() < 8 {
        return alert_message(
            session,
            "/register",
            "error",
            "Password must be at least 8 characters long",
        )
        .await;
    } else if form.password != form.confirm_password {
        return alert_message(session, "/login", "error", "Password doesnt match").await;
    }
    // Account creating and verifying
    let email = &form.email;
    let account = create_account(connection, &form.email, &form.password);
    create_user_profile(connection, &account);
    println!("\nSaved draft {} with id {}", email, account.id);
    if let Err(e) = send_verification_email(&email, &account.id.to_string(), "http://127.0.0.1:8000/verify") {
        println!("Failed to send verification email: {}", e);
        return HttpResponse::InternalServerError().finish();
    }
    return HttpResponse::Ok().body("Register Successful");
}

pub async fn logout(session: Session) -> impl Responder {
    session.purge(); // Removes all data from the session, effectively logging the user out
    return HttpResponse::Found()
        .append_header((http::header::LOCATION, "/login"))
        .finish();
}

pub async fn dashboard_get(session: Session, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();

    let user_id: Option<i32> = session.get("account_id").unwrap_or(None);
    match user_id {
        Some(id) => println!("{}", id),
        None => println!("User ID not found"),
    }

    let rendered = tera.render("accounts/dashboard.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub fn create_account(conn: &mut PgConnection, email: &str, password: &str) -> Account {
    use crate::accounts::schema::accounts;
    let hashed_password = hash(password, DEFAULT_COST).expect("Failed to hash password");
    let new_account = NewAccount {
        email,
        password: &hashed_password,
    };

    diesel::insert_into(accounts::table)
        .values(&new_account)
        .returning(Account::as_returning())
        .get_result(conn)
        .expect("Error saving new post")
}

pub fn create_user_profile(conn: &mut PgConnection, account: &Account) {
    use crate::accounts::schema::user_profiles;
    let default_profile_image = "./media/accounts/profile_images/user-thumbnail.png";
    let new_user_profile = NewUserProfile {
        account_id: account.id, // Use the ID of the newly created account
        // Set default or empty values for the user profile fields
        // These can be updated later by the user
        name: "",
        surname: "",
        phone_number: "",
        photo: Some(&default_profile_image),
    };

    diesel::insert_into(user_profiles::table)
        .values(&new_user_profile)
        .execute(conn)
        .expect("Error saving new user profile");
}

pub async fn get_user_email(user_id: i32) -> Result<String, diesel::result::Error> {
    use crate::accounts::schema::accounts::dsl::*;
    let mut connection = establish_connection(); // This function should establish a database connection

    let result = accounts
        .find(user_id)
        .select(email) // Assuming `email` is a field in your accounts table
        .first::<String>(&mut connection); // This tries to fetch the first result

    result
}

pub async fn change_profile_post(session: Session, mut payload: Multipart) -> impl Responder {
    let mut conn = establish_connection();

    let account_id_result = session.get::<i32>("account_id");
    let user_id: i32 = match account_id_result {
        Ok(Some(user_id)) => user_id,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("User is not logged in or session is expired")
        }
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };
    let mut user_profile = crate::accounts::schema::user_profiles::table
        .find(user_id)
        .first::<UserProfile>(&mut conn)
        .expect("Error loading user profile");

    // Iterate over multipart form data
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let field_name = content_disposition.get_name().unwrap_or_default();

        match field_name {
            "name" => {
                let data = field.next().await.unwrap().unwrap();
                user_profile.name = String::from_utf8(data.to_vec()).unwrap();
            }
            "surname" => {
                let data = field.next().await.unwrap().unwrap();
                user_profile.surname = String::from_utf8(data.to_vec()).unwrap();
            }
            "phone_number" => {
                let data = field.next().await.unwrap().unwrap();
                user_profile.phone_number = String::from_utf8(data.to_vec()).unwrap();
            }
            "photo" => {
                let filename =
                    sanitize_filename::sanitize(content_disposition.get_filename().unwrap());
                let photo_path = format!("./media/accounts/profile_images/{}", filename);
                let photo_path_clone = photo_path.clone();
                user_profile.photo = photo_path;
                let mut f = web::block(move || std::fs::File::create(&photo_path_clone))
                    .await
                    .unwrap();

                while let Some(chunk) = field.next().await {
                    let data = chunk.unwrap();
                    f = web::block(move || {
                        let mut file = f.expect("Failed to open file");
                        file.write_all(&data)?;
                        Ok(file) // Directly return the `File` wrapped in an `Ok`
                    })
                    .await
                    .expect("error");
                }
            }
            _ => {}
        }
    }
     let _ = diesel::update(crate::accounts::schema::user_profiles::table.find(user_id))
        .set(&user_profile)
        .execute(&mut conn)
        .expect("Error updating user profile");

    HttpResponse::Ok()
        .content_type("text/plain")
        .body("User profile created successfully!")
}

pub async fn change_profile_get(tera: web::Data<Tera>) -> impl Responder{
    let mut context = Context::new();
    let rendered = tera.render("accounts/change_profile.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
    
}

pub async fn forgot_password_get(session: Session,tera: web::Data<Tera>) -> impl Responder{
    let mut context = Context::new();
    if let Some(alert_message) = session.get::<AlertMessage>("alert_message").unwrap() {
        context.insert("alert_message", &alert_message);
        session.remove("alert_message");
    }
    let rendered = tera.render("accounts/forgot_password.html", &context).unwrap();
    actix_web::HttpResponse::Ok().content_type("text/html").body(rendered)
}

pub async fn forgot_password_post(session: Session, form: web::Form<FogotPasswordForm>) -> impl Responder{
    
    let email = &form.email;
    let account_id_result = session.get::<i32>("account_id");
    let account_id: i32 = match account_id_result {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("User is not logged in or session is expired")
        }
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    }; 
    if let Err(e) = send_verification_email(&email, &account_id.to_string(), "http://127.0.0.1:8000/reset_password") {
        println!("Failed to send verification email: {}", e);
        return HttpResponse::InternalServerError().finish();
    }
    alert_message(session, "/forgot_password", "succes", "messege to reset password was sended to your email").await 
     
}

    

pub async fn reset_password_get(tera: web::Data<Tera>, token: web::Path<String>) -> impl Responder{
    let mut context = Context::new();
    let token = token.into_inner();
    let secret = "verification"; // Use the same secret as when encoding
    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::ExpiredSignature => {
                let mut validation = Validation::default();
                validation.validate_exp = false; // Disable expiration validation
                if let Ok(token_data) = decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &validation,
                ) {
                    let user_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");

                    // Assuming you have a function `get_user_email` to fetch the user's email from the database
                    if let Ok(user_email) = get_user_email(user_id).await {
                        // Resend the verification email
                        if let Err(e) = send_verification_email(&user_email, &user_id.to_string(), "http://127.0.0.1:8000/reset_password") {
                            println!("Failed to resend verification email: {:?}", e);
                            return HttpResponse::InternalServerError()
                                .body("Failed to resend verification email");
                        }
                    }
                    return HttpResponse::Ok().body(
                        "Verification link has expired. A new verification email has been sent.",
                    );
                } else {
                    return HttpResponse::Unauthorized().body("Invalid token");
                }
            }
            _ => return HttpResponse::Unauthorized().body("Invalid token"),
        },
    };
    context.insert("token", &token);
    let rendered = tera.render("accounts/reset_password.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub async fn reset_password_post(session: Session, form: web::Form<ResetPasswordForm>, token: web::Path<String>) -> impl Responder {
    let token = token.into_inner();
    let secret = "verification"; // Use the same secret as when encoding
    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::ExpiredSignature => {
                let mut validation = Validation::default();
                validation.validate_exp = false; // Disable expiration validation
                if let Ok(token_data) = decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &validation,
                ) {
                    let user_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");

                    // Assuming you have a function `get_user_email` to fetch the user's email from the database
                    if let Ok(user_email) = get_user_email(user_id).await {
                        // Resend the verification email
                        if let Err(e) = send_verification_email(&user_email, &user_id.to_string(), "http://127.0.0.1:8000/reset_password") {
                            println!("Failed to resend verification email: {:?}", e);
                            return HttpResponse::InternalServerError()
                                .body("Failed to resend verification email");
                        }
                    }
                    return HttpResponse::Ok().body(
                        "Verification link has expired. A new verification email has been sent.",
                    );
                } else {
                    return HttpResponse::Unauthorized().body("Invalid token");
                }
            }
            _ => return HttpResponse::Unauthorized().body("Invalid token"),
        },
    };
    if form.password != form.confirm_password{
        return actix_web::HttpResponse::BadRequest().body("Passwords doesnt match");
    }
    let account_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");
    let hashed_password = hash(&form.password, DEFAULT_COST).expect("Failed to hash password");
    use crate::accounts::schema::accounts::dsl::*;
    let connection = &mut establish_connection();
    let _ = diesel::update(accounts.find(account_id))
        .set(password.eq(hashed_password))
        .execute(&mut *connection); 
    alert_message(session, "/login", "succes", "passworrd reseted").await
     
}

pub async fn profile(session: Session, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    let account_id_result = session.get::<i32>("account_id");
    let account_id: i32 = match account_id_result {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("User is not logged in or session is expired")
        }
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };
    let mut conn = establish_connection();
    let user_profile = crate::accounts::schema::user_profiles::table
        .filter(crate::accounts::schema::user_profiles::account_id.eq(account_id))
        .first::<UserProfile>(&mut conn)
        .expect("Error loading user profile");
    context.insert("name", &user_profile.name);
    context.insert("surname", &user_profile.surname);
    context.insert("phone_number", &user_profile.phone_number);
    context.insert("photo", &user_profile.photo);
    context.insert("title", "profile page");

    let rendered = tera.render("accounts/profile.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}
