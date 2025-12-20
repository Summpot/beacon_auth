use actix_web::{middleware, App, HttpServer};
use beacon_lib::{
    config::ServeConfig,
    server::{build_api_context_routes, build_app_state, build_jwks_routes},
};
use clap::Parser;
use lambda_web::{is_running_on_lambda, run_actix_on_lambda};

/// AWS Lambda / serverless entrypoint.
///
/// This binary is intended for deployments using API Gateway / Function URLs.
/// Locally, it can still run an HTTP server for development.
#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    // In many deployments there is no .env file; do not fail if missing.
    dotenvy::dotenv().ok();

    // Parse ServeConfig directly (no subcommands) so Lambda can run without argv wiring.
    let config = ServeConfig::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(config.log_level.as_str()),
    )
    .init();

    let cors_origins = config.cors_origin_list();
    let app_state = build_app_state(&config).await?;

    let factory = move || {
        let cors = {
            let mut cors = actix_cors::Cors::default()
                .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                .allowed_headers(vec![
                    actix_web::http::header::AUTHORIZATION,
                    actix_web::http::header::ACCEPT,
                    actix_web::http::header::CONTENT_TYPE,
                ])
                .max_age(3600);

            for origin in &cors_origins {
                cors = cors.allowed_origin(origin);
            }

            cors
        };

        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(build_api_context_routes())
            // Back-compat: expose JWKS at the legacy root path too.
            .service(build_jwks_routes())
    };

    if is_running_on_lambda() {
        run_actix_on_lambda(factory)
            .await
            .map_err(|e| anyhow::anyhow!("Lambda runtime error: {e}"))?;
        Ok(())
    } else {
        HttpServer::new(factory)
            .bind(&config.bind_address)?
            .run()
            .await
            .map_err(Into::into)
    }
}
