use std::{future::Future, pin::Pin, sync::Arc};

use http::{HeaderName, Request};
use tower::{Layer, Service};

use crate::core::{
    authentication::{AuthenticationResult, AuthenticationService, CompoundAuthenticationHandler},
    authorization::{AuthorizationPolicy, AuthorizationRequirement},
    http::{AuthResponse, RequestExtensions},
};

impl RequestExtensions for http::Extensions {
    fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.get()
    }

    fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.get_mut()
    }

    fn insert<T: Send + Sync + 'static>(&mut self, ext: T) -> Option<T> {
        self.insert(ext)
    }
}

impl<Body: Send + 'static> crate::core::http::Request for Request<Body> {
    type RequestExtensions = http::Extensions;

    type RequestExtensionsDeref<'a> = &'a http::Extensions;

    type RequestExtensionsDerefMut<'a> = &'a mut http::Extensions;

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
        self.extensions_mut()
    }
}

pub struct AuthenticationLayer<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    pub service: Arc<AuthenticationService<Handler>>,
}

impl<Handler> Clone for AuthenticationLayer<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

impl<S, Handler> Layer<S> for AuthenticationLayer<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    type Service = Authentication<S, Handler>;

    fn layer(&self, inner: S) -> Self::Service {
        Authentication {
            inner,
            service: self.service.clone(),
        }
    }
}

pub struct Authentication<S, Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    inner: S,
    service: Arc<AuthenticationService<Handler>>,
}

impl<S, Handler> Clone for Authentication<S, Handler>
where
    S: Clone,
    Handler: CompoundAuthenticationHandler,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            service: self.service.clone(),
        }
    }
}

impl<S, Handler, Body, AuthFut> Service<Request<Body>> for Authentication<S, Handler>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
    S::Future: Send,
    Handler: CompoundAuthenticationHandler<AuthFut = AuthFut>,
    Body: Send + 'static,
    AuthFut: Future<Output = AuthenticationResult> + Send,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move {
            this.service.authenticate(&mut req).await;
            this.inner.call(req).await
        })
    }
}

pub struct AuthorizeLayer<Handler: CompoundAuthenticationHandler, Requirement: AuthorizationRequirement>(
    AuthorizationPolicy<Handler, Requirement>,
);

impl<Handler, Requirement> AuthorizeLayer<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    pub fn new(policy: AuthorizationPolicy<Handler, Requirement>) -> Self {
        Self(policy)
    }
}

impl<Handler, Requirement> Clone for AuthorizeLayer<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, Handler, Requirement> Layer<S> for AuthorizeLayer<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    type Service = Authorize<S, Handler, Requirement>;

    fn layer(&self, inner: S) -> Self::Service {
        Authorize {
            inner,
            policy: self.0.clone(),
        }
    }
}

pub struct Authorize<S, Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    inner: S,
    policy: AuthorizationPolicy<Handler, Requirement>,
}

impl<S: Clone, Handler, Requirement> Clone for Authorize<S, Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<S, Handler, Requirement, Body, ChallengeFut, ForbidFut, AuthorizeFut> Service<Request<Body>>
    for Authorize<S, Handler, Requirement>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
    S::Future: Send,
    Handler: CompoundAuthenticationHandler<ChallengeFut = ChallengeFut, ForbidFut = ForbidFut>,
    Requirement: AuthorizationRequirement<AuthorizeFut = AuthorizeFut>,
    Body: Send + 'static,
    ChallengeFut: Future<Output = Option<AuthResponse>> + Send,
    ForbidFut: Future<Output = Option<AuthResponse>> + Send,
    AuthorizeFut: Future<Output = bool> + Send,
{
    type Response = Result<S::Response, AuthResponse>;

    type Error = S::Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move {
            match this.policy.authorize(&mut req).await {
                Ok(()) => this.inner.call(req).await.map(Ok),
                Err(response) => Ok(Err(response)),
            }
        })
    }
}
