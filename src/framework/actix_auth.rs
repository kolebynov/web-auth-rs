use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    sync::Arc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};

use crate::core::authentication::{AuthenticationService, CompoundAuthenticationHandler};

impl crate::core::http::Request for ServiceRequest {
    fn get_uri(&self) -> &http::Uri {
        self.uri()
    }

    fn get_header(&self, header: impl http::header::AsHeaderName) -> Option<&http::HeaderValue> {
        self.headers().get(header)
    }

    fn set_extension<T: Send + Sync + 'static>(&mut self, ext: T) -> Option<T> {
        self.extensions_mut().insert(ext)
    }

    fn get_extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions().get()
    }

    fn get_extension_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions_mut().get_mut()
    }
}

pub struct Authentication<Handler: CompoundAuthenticationHandler>(
    pub Arc<AuthenticationService<Handler>>,
);

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B, Handler> Transform<S, ServiceRequest> for Authentication<Handler>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    Handler: CompoundAuthenticationHandler,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S, Handler>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service,
            auth_service: self.0.clone(),
        }))
    }
}

pub struct AuthenticationMiddleware<S, Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    service: S,
    auth_service: Arc<AuthenticationService<Handler>>,
}

impl<S, B, Handler> Service<ServiceRequest> for AuthenticationMiddleware<S, Handler>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    Handler: CompoundAuthenticationHandler,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        println!("Hi from start. You requested: {}", req.path());

        let fut = self.service.call(req);

        Box::pin(async move {
            self.auth_service.authenticate(&mut req).await;

            println!("Hi from response");
            Ok(res)
        })
    }
}
