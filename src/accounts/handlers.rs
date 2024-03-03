use crate::accounts::forms::{LoginForm, RegisterForm};
use actix_session::Session;
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use tera::{Context, Tera};
// diesel
use crate::accounts::models::{Account, NewAccount};
use crate::establish_connection;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::prelude::*;
use uuid::Uuid;
// Assuming `Model` is the correct entity from your `models.rs`

async fn submit_form(session: &Session, csrf_token: &str) -> bool {
    let form_csrf_token = csrf_token;
    let session_csrf_token: Option<String> = session.get("csrf_token").expect("wrong csrf");

    match session_csrf_token {
        Some(token) if token == form_csrf_token => {
            // CSRF token is valid, proceed with form handling
            true
        }
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
