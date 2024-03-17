use actix_files as files;
use actix_web::{web, App, HttpServer, Responder, cookie::SameSite};
use tera::{Context, Tera};
use actix_session::{CookieSession, Session};
use dotenv::dotenv;
use core::panic;
use std::env;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
//modules
mod accounts;
mod admin;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn init_pool(database_url: &str) -> Pool {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder().build(manager).expect("Failed to create pool.")
}

pub fn establish_connection() -> PgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}


async fn home(session: Session,tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "My Actix App");
    context.insert("message", "Hello from Actix with context!");
    
    match session.get::<i32>("account_id"){
        Ok(Some(user_id)) => println!("user_id: {}", &user_id),
        Ok(None) => println!("user not found"),
        Err(_) => println!("Error when tried get user")
    };

    let rendered = match tera.render("home.html", &context){
        Ok(rendered) => rendered,
        Err(_) => panic!("Error while rendering template")
    };
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}




#[actix_web::main]
async fn main() -> std::io::Result<()> {

    dotenv().ok(); // Load .env file if available
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = init_pool(&database_url); // Initialize the connection pool
 
    let tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*")).unwrap();

    println!("Server 127.0.0.1:8000");
    HttpServer::new(move || {
        App::new()
            .wrap(CookieSession::signed(&[0; 32]) // Use a secret key for signed cookies
                    .secure(false) // Set to true in production over HTTPS
                    .same_site(SameSite::Strict)
                    .max_age(24 * 60 * 60),)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(tera.clone()))
            .route("/", web::get().to(home))
            .configure(admin::routes::config)
            .configure(accounts::routes::config)
            .service(files::Files::new("/static", "static").show_files_listing())
            .service(files::Files::new("/media", "media").show_files_listing())
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await 
}

