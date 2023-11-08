use axum_core::response::IntoResponse;

use crate::core::http::AuthResponse;

impl IntoResponse for AuthResponse {
    fn into_response(self) -> axum_core::response::Response {
        let mut response = self.status_code.into_response();
        *response.headers_mut() = self.headers;

        response
    }
}
