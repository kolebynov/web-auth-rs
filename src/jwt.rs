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
    principal::{ClaimPlainValue, ClaimValue, UserPrincipal},
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
                .filter_map(|(t, v)| json_to_claim_value(v).map(|c| (t, c)))
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

fn json_to_claim_value(json_value: serde_json::Value) -> Option<ClaimValue> {
    match json_value {
        serde_json::Value::Array(arr) if !arr.is_empty() => json_arr_to_plain_values(arr).map(ClaimValue::Array),
        serde_json::Value::Array(_) => None,
        _ => json_to_plain_value(json_value).map(ClaimValue::PlainValue),
    }
}

fn json_arr_to_plain_values(arr: Vec<serde_json::Value>) -> Option<Vec<ClaimPlainValue>> {
    let result = arr.into_iter().filter_map(json_to_plain_value).collect::<Vec<_>>();

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn json_to_plain_value(json_value: serde_json::Value) -> Option<ClaimPlainValue> {
    match json_value {
        serde_json::Value::Bool(b) => Some(ClaimPlainValue::Bool(b)),
        serde_json::Value::Number(num) => {
            if num.is_f64() {
                Some(ClaimPlainValue::Float(num.as_f64().unwrap()))
            } else {
                num.as_i64().map(ClaimPlainValue::Int)
            }
        }
        serde_json::Value::String(s) => Some(ClaimPlainValue::String(s)),
        serde_json::Value::Null => None,
        _ => Some(ClaimPlainValue::String(json_value.to_string())),
    }
}
