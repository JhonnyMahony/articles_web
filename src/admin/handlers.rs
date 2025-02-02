use crate::accounts::models::Account;
use crate::accounts::schema::accounts;
use crate::Pool;
use actix_web::{web, HttpResponse, Responder, http};
use diesel::{query_dsl::methods::FilterDsl, ExpressionMethods, RunQueryDsl};
use tera::{Context, Tera};

pub async fn dashboard_get(tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "You on dashboard");
    let rendered = match tera.render("admin/admin/dashboard.html", &context) {
        Ok(html) => html,
        Err(e) => {
            eprintln!("Template rendering error: {}", e); // Log the error for debugging
            return HttpResponse::InternalServerError().body("Internal Server Error");
        }
    };
    HttpResponse::Ok().content_type("text/html").body(rendered)
}

pub async fn model_detail(pool: web::Data<Pool>, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    let mut db_conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return HttpResponse::BadRequest().body("Error"),
    };
    context.insert("title", "Model detail");
    match accounts::dsl::accounts.load::<Account>(&mut db_conn) {
        Ok(users) => context.insert("accounts", &users),
        Err(_) => return HttpResponse::BadRequest().body("Error"),
    };


    let rendered = match tera.render("admin/admin/model_detail.html", &context) {
        Ok(html) => html,
        Err(e) => {
            eprintln!("Template rendering error: {}", e); // Log the error for debugging
            return HttpResponse::InternalServerError().body("Internal Server Error");
        }
    };
    HttpResponse::Ok().content_type("text/html").body(rendered)
                                                                                                                                                                        
}

pub async fn item_detail_get(id: web::Path<i32>, pool: web::Data<Pool>, tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "you on item detail page");
    let id = id.into_inner();
    let mut db_conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return HttpResponse::BadRequest().body("cant get data")
    };
    
    let account = match accounts::dsl::accounts.filter(accounts::dsl::id.eq(id)).first::<Account>(&mut db_conn){
        Ok(conn) => conn,
        Err(_) => return HttpResponse::BadRequest().body("cant get Account from database")
    };
    context.insert("account", &account);
    let rendered = tera.render("admin/admin/item_detail.html", &context).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}

pub async fn item_delete(pool: web::Data<Pool>, id: web::Path<i32>) -> impl Responder {
    let id = id.into_inner();
    let mut db_conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return HttpResponse::BadRequest().body("cant get data")
    };
    
    match diesel::delete(accounts::dsl::accounts.filter(accounts::dsl::id.eq(id))).execute(&mut db_conn){
        Ok(conn) => conn,
        Err(_) => return HttpResponse::BadRequest().body("cant delete item")
    };
    return HttpResponse::Found()
        .append_header((http::header::LOCATION, "/model_detail"))
        .finish();
    
}








