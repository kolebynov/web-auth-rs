use std::collections::HashMap;

use async_trait::async_trait;
use http::{
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
    HeaderMap, HeaderValue, StatusCode,
};
use jsonwebtoken::{DecodingKey, Validation};

use crate::core::{
    authentication::{AuthenticationError, AuthenticationHandler, AuthenticationResult},
    http::{AuthResponse, Request},
    principal::{AuthenticatedPrincipal, Claim},
};

pub struct JwtBearerHandler {
    pub validation_opt: Validation,
    pub decoding_key: DecodingKey,
}

#[async_trait]
impl AuthenticationHandler for JwtBearerHandler {
    async fn authenticate(&self, request: &mut impl Request) -> AuthenticationResult {
        let bearer_token = request
            .get_header(AUTHORIZATION)
            .and_then(|h| {
                let header_str = h.to_str().ok()?;
                if header_str.starts_with("Bearer ") {
                    header_str.get(7..)
                } else {
                    None
                }
            })
            .ok_or(AuthenticationError::NoResult)?;

        let claims = jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(
            bearer_token,
            &self.decoding_key,
            &self.validation_opt,
        )
        .map_err(|e| AuthenticationError::Fail(e.into()))?
        .claims;

        Ok(AuthenticatedPrincipal {
            claims: claims
                .into_iter()
                .map(|pair| Claim {
                    kind: pair.0,
                    value: json_to_claim_value(pair.1),
                })
                .collect(),
        })
    }

    async fn challenge(&self) -> AuthResponse {
        AuthResponse {
            status_code: StatusCode::UNAUTHORIZED,
            headers: HeaderMap::from_iter([(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))]),
        }
    }

    async fn forbid(&self) -> AuthResponse {
        AuthResponse {
            status_code: StatusCode::FORBIDDEN,
            headers: HeaderMap::default(),
        }
    }
}

fn json_to_claim_value(json_value: serde_json::Value) -> String {
    match json_value {
        serde_json::Value::String(str) => str,
        _ => json_value.to_string(),
    }
}
