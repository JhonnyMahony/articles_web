use actix_web::web;
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
        .service(web::resource("/change_profile")
            .route(web::get().to(handlers::change_profile_get))
            .route(web::post().to(handlers::change_profile_post))
        )
        .service(web::resource("/forgot_password")
            .route(web::get().to(handlers::forgot_password_get))
            .route(web::post().to(handlers::forgot_password_post))
        
        )
        .service(web::resource("/reset_password/{token}")
            .route(web::get().to(handlers::reset_password_get))
            .route(web::post().to(handlers::reset_password_post))
        )
        .service(web::resource("/profile")
            .route(web::get().to(handlers::profile))
        )
        .service(web::resource("/verify/{token}")
            .route(web::get().to(handlers::verify_account))
        );
}

