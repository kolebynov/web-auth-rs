use std::{
    collections::HashMap,
    future::{ready, Ready},
};

use http::{
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
    HeaderMap, HeaderValue, StatusCode,
};
use jsonwebtoken::{DecodingKey, Validation};

use crate::core::{
    authentication::{AuthenticationError, AuthenticationHandler, AuthenticationResult},
    http::{AuthResponse, Request},
    principal::{Claim, UserPrincipal},
};

pub struct JwtBearerHandler {
    pub validation_opt: Validation,
    pub decoding_key: DecodingKey,
}

impl AuthenticationHandler for JwtBearerHandler {
    type AuthFut = Ready<AuthenticationResult>;

    type ChallengeFut = Ready<AuthResponse>;

    type ForbidFut = Ready<AuthResponse>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut {
        let bearer_token = request.get_header(&AUTHORIZATION).and_then(|h| {
            let header_str = h.to_str().ok()?;
            if header_str.starts_with("Bearer ") {
                header_str.get(7..)
            } else {
                None
            }
        });

        let Some(bearer_token) = bearer_token else {
            return ready(Err(AuthenticationError::NoResult));
        };

        let claims = jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(
            bearer_token,
            &self.decoding_key,
            &self.validation_opt,
        );

        let claims = match claims {
            Ok(token_data) => token_data.claims,
            Err(err) => return ready(Err(AuthenticationError::Fail(err.into()))),
        };

        ready(Ok(UserPrincipal {
            claims: claims
                .into_iter()
                .map(|pair| Claim {
                    kind: pair.0,
                    value: json_to_claim_value(pair.1),
                })
                .collect(),
        }))
    }

    fn challenge(&self) -> Self::ChallengeFut {
        ready(AuthResponse {
            status_code: StatusCode::UNAUTHORIZED,
            headers: HeaderMap::from_iter([(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))]),
        })
    }

    fn forbid(&self) -> Self::ForbidFut {
        ready(AuthResponse {
            status_code: StatusCode::FORBIDDEN,
            headers: HeaderMap::default(),
        })
    }
}

fn json_to_claim_value(json_value: serde_json::Value) -> String {
    match json_value {
        serde_json::Value::String(str) => str,
        _ => json_value.to_string(),
    }
}
