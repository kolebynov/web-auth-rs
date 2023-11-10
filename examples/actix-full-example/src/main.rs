use std::{error::Error, net::SocketAddr, str::FromStr, sync::Arc};

use actix_web::{
    web::{self, ReqData},
    App, HttpServer, Responder,
};
use web_auth_rs::{
    core::{
        authentication::{AuthenticationServiceBuilder, SuccessAuthenticationResult},
        authorization::AuthorizationPolicyBuilder,
    },
    framework::actix_auth::{Authentication, Authorize},
    jsonwebtoken::{DecodingKey, Validation},
    jwt::JwtBearerHandler,
};

async fn test_get(auth_result: ReqData<SuccessAuthenticationResult>) -> impl Responder {
    format!("<pre>hello world:\n{:#?}</pre>", auth_result.principal)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    HttpServer::new(|| {
        let mut validation = Validation::default();
        validation.sub = Some("subject".to_owned());
        validation.set_issuer(&["issuer"]);
        validation.validate_exp = true;

        let jwt_handler = JwtBearerHandler {
            validation_opt: validation,
            decoding_key: DecodingKey::from_secret("1234567890123456".as_bytes()),
        };

        let auth_service = Arc::new(
            AuthenticationServiceBuilder::new()
                .add_authentication_handler("Bearer".to_owned(), jwt_handler)
                .set_default_scheme("Bearer".to_owned())
                .build()
                .unwrap(),
        );

        let authorize = Authorize::new(
            AuthorizationPolicyBuilder::new()
                .require_role("test".to_owned())
                .build(auth_service.clone()),
        );

        App::new()
            .route("/{tail:.*}", web::get().to(test_get).wrap(authorize))
            .wrap(Authentication(auth_service))
    })
    .bind(&SocketAddr::from_str("0.0.0.0:8000")?)?
    .run()
    .await?;

    Ok(())
}
