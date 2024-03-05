use crate::accounts::forms::{Claims, LoginForm, RegisterForm};
use actix_session::Session;
use actix_web::cookie::time::format_description::parse;
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind};
use tera::{Context, Tera};
// diesel
use crate::accounts::models::{Account, NewAccount};
use crate::establish_connection;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::{prelude::*, result};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{message::Mailbox, Message, SmtpTransport, Transport};
use uuid::Uuid;
// Assuming `Model` is the correct entity from your `models.rs`

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
                        if let Err(e) = send_verification_email(&user_email, &user_id.to_string()) {
                            println!("Failed to resend verification email: {:?}", e);
                            return HttpResponse::InternalServerError().body("Failed to resend verification email");
                        }
                    }
                    return HttpResponse::Ok().body("Verification link has expired. A new verification email has been sent.");
                } else {
                    return HttpResponse::Unauthorized().body("Invalid token");
                }
            },
            _ => return HttpResponse::Unauthorized().body("Invalid token"),
        },
    };

    let account_id: i32 = token_data.claims.sub.parse().expect("Invalid ID");
    let _ = diesel::update(accounts.find(account_id))
        .set(is_verified.eq(true))
        .execute(&mut *connection);
    // Use `user_id` to find the user in your database and mark them as verified
    // Database interaction logic goes here...

    HttpResponse::Ok().body("Account verified")
}

fn send_verification_email(email: &str, user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
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
            "Please click on the link to verify your account: http://127.0.0.1:8000/verify/{}",
            token
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
    // Here you can insert your authentication logic
    let connection = &mut establish_connection();

    let is_form_valid = submit_form(&session, &form.csrf_token).await;
    if !is_form_valid {
        return HttpResponse::Ok().body("uncorrect csrf");
    }
    let results = accounts
        .filter(email.eq(&form.email))
        .limit(5)
        .select(Account::as_select())
        .load(connection)
        .expect("Error loading posts");

    if results.is_empty() {
        return HttpResponse::Ok().body("User not found.");
    }
    let user_id = &results[0].id;
    let is_verifyde = &results[0].is_verified;
    println!("{}", is_verifyde);
    if let Err(e) = session.insert("user_id", &user_id.to_string()) {
        // Handle the error, e.g., by logging or returning an error response
        println!("Failed to insert user_id into session: {:?}", e);
    }
    match verify(&form.password, &results[0].password) {
        Ok(is_password_correct) => {
            if is_password_correct {
                // If the password is correct, redirect to the dashboard
                return HttpResponse::Found()
                    .append_header((http::header::LOCATION, "/dashboard"))
                    .finish();
            } else {
                // If the password is incorrect, inform the user
                return HttpResponse::Ok().body("Incorrect password");
            }
        }
        Err(_) => {
            // Handle the error case, e.g., logging the error or informing the user
            return HttpResponse::InternalServerError()
                .body("An error occurred during password verification");
        }
    }
}

pub async fn login_get(
    request: HttpRequest,
    session: Session,
    tera: web::Data<Tera>,
) -> impl Responder {
    let csrf_token = Uuid::new_v4().to_string();
    let _ = session.insert("csrf_token", &csrf_token);

    let mut context = Context::new();
    context.insert("title", "you on login page");
    context.insert("csrf_token", &csrf_token);

    let rendered = tera.render("accounts/login.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub async fn register_get(tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "you on regoster page");
    let rendered = tera.render("accounts/register.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}

pub async fn register_post(form: web::Form<RegisterForm>) -> impl Responder {
    let connection = &mut establish_connection();

    if form.password != form.confirm_password {
        return HttpResponse::Ok().body("password doesnt match");
    }

    let email_1 = &form.email;
    let password_1 = &form.password;

    let account = create_account(connection, &email_1, &password_1);
    println!("\nSaved draft {} with id {}", email_1, account.id);
    if let Err(e) = send_verification_email(&email_1, &account.id.to_string()) {
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

    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
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
pub async fn get_user_email(user_id: i32) -> Result<String, diesel::result::Error> {
    use crate::accounts::schema::accounts::dsl::*;
    let mut connection = establish_connection(); // This function should establish a database connection
    
    let result = accounts
        .find(user_id)
        .select(email) // Assuming `email` is a field in your accounts table
        .first::<String>(&mut connection); // This tries to fetch the first result

    result
}
