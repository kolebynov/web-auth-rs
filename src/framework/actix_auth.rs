use std::{
    cell::{Ref, RefMut},
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, ResponseError,
};
use http::HeaderName;

use crate::core::{
    authentication::{AuthenticationService, CompoundAuthenticationHandler},
    authorization::{AuthorizationPolicy, AuthorizationRequirement},
    http::{AuthResponse, RequestExtensions},
};

impl RequestExtensions for actix_web::dev::Extensions {
    fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        actix_web::dev::Extensions::get(self)
    }

    fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        actix_web::dev::Extensions::get_mut(self)
    }

    fn insert<T: Send + Sync + 'static>(&mut self, ext: T) -> Option<T> {
        actix_web::dev::Extensions::insert(self, ext)
    }
}

impl crate::core::http::Request for ServiceRequest {
    type RequestExtensions = actix_web::dev::Extensions;

    type RequestExtensionsDeref<'a> = Ref<'a, Self::RequestExtensions>;

    type RequestExtensionsDerefMut<'a> = RefMut<'a, Self::RequestExtensions>;

    fn get_uri(&self) -> &http::Uri {
        self.uri()
    }

    fn get_header(&self, header: &HeaderName) -> Option<&http::HeaderValue> {
        self.headers().get(header)
    }

    fn get_extensions(&self) -> Self::RequestExtensionsDeref<'_> {
        self.extensions()
    }

    fn get_extensions_mut(&mut self) -> Self::RequestExtensionsDerefMut<'_> {
        (*self).extensions_mut()
    }
}

impl ResponseError for AuthResponse {
    fn status_code(&self) -> http::StatusCode {
        self.status_code
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        let mut res = actix_web::HttpResponse::new(self.status_code());
        for (name, value) in self.headers.iter() {
            res.headers_mut().insert(name.clone(), value.clone());
        }

        res
    }
}

pub struct Authentication<Handler: CompoundAuthenticationHandler>(pub Arc<AuthenticationService<Handler>>);

impl<S, B, Handler> Transform<S, ServiceRequest> for Authentication<Handler>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
            inner: Rc::new(service),
            auth_service: self.0.clone(),
        }))
    }
}

pub struct AuthenticationMiddleware<S, Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    inner: Rc<S>,
    auth_service: Arc<AuthenticationService<Handler>>,
}

impl<S, B, Handler> Service<ServiceRequest> for AuthenticationMiddleware<S, Handler>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Handler: CompoundAuthenticationHandler,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(inner);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let auth_service = self.auth_service.clone();
        let inner = self.inner.clone();

        Box::pin(async move {
            auth_service.authenticate(&mut req).await;
            inner.call(req).await
        })
    }
}

pub struct Authorize<Handler: CompoundAuthenticationHandler, Requirement: AuthorizationRequirement>(
    AuthorizationPolicy<Handler, Requirement>,
);

impl<Handler, Requirement> Authorize<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    pub fn new(policy: AuthorizationPolicy<Handler, Requirement>) -> Self {
        Self(policy)
    }
}

impl<S, B, Handler, Requirement> Transform<S, ServiceRequest> for Authorize<Handler, Requirement>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthorizeMiddleware<S, Handler, Requirement>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthorizeMiddleware {
            inner: Rc::new(service),
            policy: self.0.clone(),
        }))
    }
}

pub struct AuthorizeMiddleware<S, Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    inner: Rc<S>,
    policy: AuthorizationPolicy<Handler, Requirement>,
}

impl<S, B, Handler, Requirement> Service<ServiceRequest> for AuthorizeMiddleware<S, Handler, Requirement>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(inner);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let policy = self.policy.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            match policy.authorize(&mut req).await {
                Ok(()) => inner.call(req).await,
                Err(response) => Err(response.into()),
            }
        })
    }
}
