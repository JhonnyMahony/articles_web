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
        )
        .service(
            web::resource("/dashboard")
                .route(web::get().to(handlers::dashboard_get))
        )
        .service(
            web::resource("/logout")
                .route(web::get().to(handlers::logout))
        )
        .service(web::resource("/create_user_profile")
            .route(web::post().to(handlers::user_profile_create))
        )
        .service(web::resource("/profile")
            .route(web::get().to(handlers::profile))
        )
        .service(web::resource("/verify/{token}")
            .route(web::get().to(handlers::verify_account))
        );
        


}

