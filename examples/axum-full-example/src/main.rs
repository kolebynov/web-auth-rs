use std::{net::SocketAddr, str::FromStr, sync::Arc};

use axum::{response::Html, routing::get, BoxError, Extension, Router};
use web_auth_rs::{
    core::{
        authentication::{AuthenticationServiceBuilder, SuccessAuthenticationResult},
        authorization::AuthorizationPolicyBuilder,
    },
    framework::tower_auth::{AuthenticationLayer, AuthorizeLayer},
    jsonwebtoken::{DecodingKey, Validation},
    jwt::JwtBearerHandler,
};

async fn test_get(Extension(auth_result): Extension<SuccessAuthenticationResult>) -> Html<String> {
    Html(format!("<pre>hello world:\n{:#?}</pre>", auth_result.principal))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
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

    let authorize_layer = AuthorizeLayer::new(
        AuthorizationPolicyBuilder::new()
            .require_role("test".to_owned())
            .build(auth_service.clone()),
    );

    let router = Router::new()
        .route("/*rest", get(test_get).layer(authorize_layer))
        .layer(AuthenticationLayer { service: auth_service });

    axum::Server::try_bind(&SocketAddr::from_str("0.0.0.0:8000")?)?
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
