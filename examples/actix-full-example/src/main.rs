use std::{error::Error, net::SocketAddr, str::FromStr};

use actix_web::{web, App, HttpServer, Responder};

async fn test_get() -> impl Responder {
    "Hello world"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    HttpServer::new(|| App::new().route("/{tail:.*}", web::get().to(test_get)))
        .bind(&SocketAddr::from_str("0.0.0.0:8001")?)?
        .run()
        .await?;

    Ok(())
}
