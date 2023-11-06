use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

use http::{Request, Response};
use tower::{Layer, Service};

use crate::core::{
    authentication::{AuthenticationService, CompoundAuthenticationHandler},
    authorization::{AuthorizationPolicy, AuthorizationRequirement},
};

impl<Body: Send + 'static> crate::core::http::Request for Request<Body> {
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

pub struct AuthenticationLayer<Handler> {
    pub service: Arc<AuthenticationService<Handler>>,
}

impl<Handler> Clone for AuthenticationLayer<Handler> {
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

pub struct Authentication<S, Handler> {
    inner: S,
    service: Arc<AuthenticationService<Handler>>,
}

impl<S: Clone, Handler> Clone for Authentication<S, Handler> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            service: self.service.clone(),
        }
    }
}

impl<S, Handler, Body> Service<Request<Body>> for Authentication<S, Handler>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
    S::Future: Send,
    Handler: CompoundAuthenticationHandler,
    Body: Send + 'static,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
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

pub struct AuthorizeLayer<Handler, Requirement, ResBody>(
    AuthorizationPolicy<Handler, Requirement>,
    PhantomData<ResBody>,
);

impl<Handler, Requirement, ResBody> AuthorizeLayer<Handler, Requirement, ResBody>
where
    Requirement: AuthorizationRequirement,
{
    pub fn new(policy: AuthorizationPolicy<Handler, Requirement>) -> Self {
        Self(policy, PhantomData)
    }
}

impl<Handler, Requirement, ResBody> Clone for AuthorizeLayer<Handler, Requirement, ResBody>
where
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<S, Handler, Requirement, ResBody> Layer<S> for AuthorizeLayer<Handler, Requirement, ResBody>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    type Service = Authorize<S, Handler, Requirement, ResBody>;

    fn layer(&self, inner: S) -> Self::Service {
        Authorize {
            inner,
            policy: self.0.clone(),
            _phantom: PhantomData,
        }
    }
}

pub struct Authorize<S, Handler, Requirement, ResBody> {
    inner: S,
    policy: AuthorizationPolicy<Handler, Requirement>,
    _phantom: PhantomData<ResBody>,
}

impl<S: Clone, Handler, Requirement, ResBody> Clone for Authorize<S, Handler, Requirement, ResBody>
where
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, Handler, Requirement, Body, ResBody> Service<Request<Body>>
    for Authorize<S, Handler, Requirement, ResBody>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
    S::Future: Send,
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
    Body: Send + 'static,
    ResBody: Default + Send + Sync + 'static,
{
    type Response = Result<S::Response, Response<ResBody>>;

    type Error = S::Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
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

impl<B: Default + Send + Sync + 'static> crate::core::http::Response for http::Response<B> {
    fn set_status_code(&mut self, status_code: http::StatusCode) {
        *self.status_mut() = status_code;
    }

    fn set_header(&mut self, header: impl http::header::IntoHeaderName, value: http::HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}
