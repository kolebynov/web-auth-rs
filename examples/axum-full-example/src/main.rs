use std::{net::SocketAddr, str::FromStr, sync::Arc};

use axum::{body::Body, response::Html, routing::get, BoxError, Extension, Router};
use web_auth_rs::{
    core::{
        authentication::AuthenticationServiceBuilder,
        authorization::{AuthorizationPolicy, IsInRoleRequirement},
        principal::AuthenticatedPrincipal,
    },
    framework::tower::{AuthenticationLayer, AuthorizeLayer},
    jsonwebtoken::{DecodingKey, Validation},
    jwt::JwtBearerHandler,
};

async fn axum_test_get(Extension(user): Extension<AuthenticatedPrincipal>) -> Html<String> {
    Html(format!("<pre>hello world:\n{:#?}</pre>", user))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut validation = Validation::default();
    validation.sub = Some("subject".to_owned());
    validation.set_issuer(&["issuer"]);
    validation.validate_exp = true;

    let jwt_handler_1 = JwtBearerHandler {
        validation_opt: validation.clone(),
        decoding_key: DecodingKey::from_secret("1234567890123456".as_bytes()),
    };

    let jwt_handler_2 = JwtBearerHandler {
        validation_opt: validation,
        decoding_key: DecodingKey::from_secret("1234567890123459".as_bytes()),
    };

    let auth_service = Arc::new(
        AuthenticationServiceBuilder::new()
            .add_authentication_handler("Bearer 1".to_owned(), jwt_handler_1)
            .add_authentication_handler("Bearer 2".to_owned(), jwt_handler_2)
            .set_default_scheme("Bearer 2".to_owned())
            .build()
            .unwrap(),
    );

    let router = Router::new()
        .route(
            "/*rest",
            get(axum_test_get).layer(AuthorizeLayer::<_, _, Body>::new(
                AuthorizationPolicy::new(auth_service.clone())
                    .add_requirement(IsInRoleRequirement("test".to_owned())),
            )),
        )
        .layer(AuthenticationLayer {
            service: auth_service,
        });

    axum::Server::try_bind(&SocketAddr::from_str("0.0.0.0:8000")?)?
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
