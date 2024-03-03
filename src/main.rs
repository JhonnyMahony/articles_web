use actix_files as files;
use actix_web::{web, App, HttpServer, Responder};
use tera::{Context, Tera};
use actix_session::CookieSession;
use dotenv::dotenv;
use std::env;
use diesel::pg::PgConnection;
use diesel::prelude::*;
//modules
mod accounts;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}


async fn home(tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "My Actix App");
    context.insert("message", "Hello from Actix with context!");

    let rendered = tera.render("home.html", &context).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered)
}




#[actix_web::main]
async fn main() -> std::io::Result<()> {
    
    let tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*")).unwrap();
    println!("Server 127.0.0.1:8000");
    HttpServer::new(move || {
        App::new()
            .wrap(CookieSession::signed(&[0; 32]) // Use a secret key for signed cookies
                    .secure(false) // Set to true in production over HTTPS
                    .max_age(24 * 60 * 60),)
            .app_data(web::Data::new(tera.clone()))
            .route("/", web::get().to(home))
            .configure(accounts::routes::config)

            .service(files::Files::new("/static", "static").show_files_listing())
            .service(files::Files::new("/media", "media").show_files_listing())
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
    
}
