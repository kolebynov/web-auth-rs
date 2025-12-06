use std::{collections::HashMap, convert::Infallible, sync::Arc};

use axum::{
    BoxError, Extension, Json, Router,
    body::Body,
    response::{Html, Response},
    routing::get,
};
use serde::Serialize;
use serde_json::{Value, json};
use web_auth_rs::{
    core::{
        authentication::{AuthenticationServiceBuilder, SuccessAuthenticationResult},
        authorization::AuthorizationPolicyBuilder,
    },
    framework::tower_auth::{AuthenticationLayer, AuthorizeLayer},
    jsonwebtoken::{self, DecodingKey, EncodingKey, Header, Validation},
    jwt::{JwtBearerHandler, JwtTokenSource},
};

static KEY: &[u8] = b"1234567890123456";

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
}

async fn get_token() -> Json<TokenResponse> {
    let mut claims = HashMap::new();
    claims.insert("sub".to_string(), Value::String("subject".to_string()));
    claims.insert("iss".to_string(), Value::String("issuer".to_string()));
    claims.insert("role".to_string(), Value::String("test".to_string()));
    claims.insert("exp".to_string(), json!(2111111111));
    let token = jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(KEY)).unwrap();
    Json(TokenResponse { access_token: token })
}

async fn get_token_cookie() -> Response {
    let token = get_token().await.0.access_token;
    Response::builder()
        .header("Set-Cookie", format!("access_token={}; HttpOnly; Path=/", &token))
        .status(200)
        .body(Body::empty())
        .unwrap()
}

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
        decoding_key: DecodingKey::from_secret(KEY),
        token_sources: vec![
            JwtTokenSource::AuthorizationHeader,
            JwtTokenSource::Cookie("access_token".to_string()),
        ],
    };

    let auth_service = Arc::new(
        AuthenticationServiceBuilder::new()
            .add_authentication_handler("Bearer".to_owned(), jwt_handler)
            .set_default_scheme("Bearer".to_owned())
            .build()
            .unwrap(),
    );

    let authentication_layer = AuthenticationLayer {
        service: auth_service.clone(),
    };

    let authorize_layer = AuthorizeLayer::new(
        AuthorizationPolicyBuilder::new()
            .require_role("test".to_owned())
            .build(auth_service.clone()),
    );

    let router = Router::new()
        .route("/get_token", get(get_token))
        .route("/get_token_cookie", get(get_token_cookie))
        .fallback(
            get(test_get)
                .layer::<_, Infallible>(authorize_layer)
                .layer::<_, Infallible>(authentication_layer),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, router).await?;

    Ok(())
}
