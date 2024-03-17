use actix_web::web;
use crate::admin::handlers;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        .service(
            web::resource("/admin/dashboard")
                .route(web::get().to(handlers::dashboard_get))
                //.route(web::post().to(handlers::login_post)),
        )
        .service(
            web::resource("/admin/model_detail")
                .route(web::get().to(handlers::model_detail))
        )   
        .service(
            web::resource("/admin/item_detail/{id}")
                .route(web::get().to(handlers::item_detail_get)));
}

