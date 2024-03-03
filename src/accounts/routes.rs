use actix_web::web::{self};
use crate::accounts::handlers;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        .service(
            web::resource("/login")
                .route(web::get().to(handlers::login_get))
                .route(web::post().to(handlers::login_post)),
        )
        .service(
            web::resource("/register")
                .route(web::get().to(handlers::register_get))
                .route(web::post().to(handlers::register_post)), 
        );
}

