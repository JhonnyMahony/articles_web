use crate::accounts::forms::{LoginForm, RegisterForm};
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use tera::{Context, Tera};
// diesel
use crate::accounts::models::{Account, NewAccount};
use crate::establish_connection;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::prelude::*;
// Assuming `Model` is the correct entity from your `models.rs`
pub async fn login_post(form: web::Form<LoginForm>) -> impl Responder {
    println!("Username: {}", form.email);
    println!("Password: {}", form.password);
    use crate::accounts::schema::accounts::dsl::*;
    // Here you can insert your authentication logic
    let connection = &mut establish_connection();

    let results = accounts
        .filter(email.eq(&form.email))
        .limit(5)
        .select(Account::as_select())
        .load(connection)
        .expect("Error loading posts");

    println!("Displaying {} accounts", results.len());
    for account in &results {
        println!("{}", account.email);
        println!("-----------");
        println!("{}", account.password);
    }
    let is_password_correct = verify(&form.password, &results[0].password).expect("Bool");
    if is_password_correct {
        return HttpResponse::Ok().body("Login Successful");
    } else {
        HttpResponse::Ok().body("Login error")
    }
}

pub async fn login_get(
    request: HttpRequest,
    session: Session,
    tera: web::Data<Tera>,
) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "you on login page");

    // Get the client's IP address

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

    println!("Username: {}", form.email);
    println!("Password: {}", form.password);
    println!("Confirm password: {}", form.confirm_password);

    if form.password != form.confirm_password {
        return HttpResponse::Ok().body("password doesnt match");
    }

    let email_1 = &form.email;
    let password_1 = &form.password;

    let account = create_account(connection, &email_1, &password_1);
    println!("\nSaved draft {} with id {}", email_1, account.id);

    return HttpResponse::Ok().body("Login Successful");
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
