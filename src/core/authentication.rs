use async_trait::async_trait;

use super::{
    http::{Request, Response},
    principal::AuthenticatedPrincipal,
};

pub enum AuthenticationError {
    NoResult,
    Fail(anyhow::Error),
}

pub type AuthenticationResult = Result<AuthenticatedPrincipal, AuthenticationError>;

#[async_trait]
pub trait AuthenticationHandler: Send + Sync + 'static {
    async fn authenticate(&self, request: &mut impl Request) -> AuthenticationResult;

    async fn challenge(&self, response: &mut impl Response);

    async fn forbid(&self, response: &mut impl Response);
}

#[async_trait]
pub trait CompoundAuthenticationHandler: Send + Sync + 'static {
    async fn authenticate(&self, request: &mut impl Request) -> AuthenticationResult;

    async fn challenge(&self, scheme: &str, response: &mut impl Response) -> bool;

    async fn forbid(&self, scheme: &str, response: &mut impl Response) -> bool;
}

pub struct AuthenticationHandlerWithScheme<Handler: AuthenticationHandler> {
    pub scheme: String,
    pub handler: Handler,
}

#[async_trait]
impl<H> CompoundAuthenticationHandler for AuthenticationHandlerWithScheme<H>
where
    H: AuthenticationHandler,
{
    async fn authenticate(&self, request: &mut impl Request) -> AuthenticationResult {
        self.handler.authenticate(request).await
    }

    async fn challenge(&self, scheme: &str, response: &mut impl Response) -> bool {
        if scheme == self.scheme {
            self.handler.challenge(response).await;
            true
        } else {
            false
        }
    }

    async fn forbid(&self, scheme: &str, response: &mut impl Response) -> bool {
        if scheme == self.scheme {
            self.handler.forbid(response).await;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl<H1, H2> CompoundAuthenticationHandler for (H1, H2)
where
    H1: CompoundAuthenticationHandler,
    H2: CompoundAuthenticationHandler,
{
    async fn authenticate(&self, request: &mut impl Request) -> AuthenticationResult {
        let result = self.0.authenticate(request).await;
        if result.is_ok() {
            result
        } else {
            self.1.authenticate(request).await
        }
    }

    async fn challenge(&self, scheme: &str, response: &mut impl Response) -> bool {
        let challenged = self.0.challenge(scheme, response).await;
        if challenged {
            challenged
        } else {
            self.1.challenge(scheme, response).await
        }
    }

    async fn forbid(&self, scheme: &str, response: &mut impl Response) -> bool {
        let forbid = self.0.forbid(scheme, response).await;
        if forbid {
            forbid
        } else {
            self.1.forbid(scheme, response).await
        }
    }
}

pub struct AuthenticationService<Handler> {
    handler: Handler,
    default_scheme: String,
}

impl<Handler: CompoundAuthenticationHandler> AuthenticationService<Handler> {
    pub async fn authenticate(&self, request: &mut impl Request) {
        let result = self.handler.authenticate(request).await;
        match result {
            Ok(user) => {
                request.set_extension(user);
            }
            Err(err) => {
                request.set_extension(err);
            }
        };
    }

    pub async fn challenge(&self, scheme: Option<&str>, response: &mut impl Response) {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        if !self.handler.challenge(scheme, response).await {
            panic!("Scheme {scheme} is not configured");
        }
    }

    pub async fn forbid(&self, scheme: Option<&str>, response: &mut impl Response) {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        if !self.handler.forbid(scheme, response).await {
            panic!("Scheme {scheme} is not configured");
        }
    }
}

pub struct AuthenticationServiceBuilder<Handler> {
    handler: Handler,
    default_scheme: Option<String>,
}

impl AuthenticationServiceBuilder<()> {
    pub fn new() -> AuthenticationServiceBuilder<()> {
        AuthenticationServiceBuilder {
            handler: (),
            default_scheme: None,
        }
    }

    pub fn add_authentication_handler<H: AuthenticationHandler>(
        self,
        scheme: String,
        handler: H,
    ) -> AuthenticationServiceBuilder<AuthenticationHandlerWithScheme<H>> {
        AuthenticationServiceBuilder {
            handler: AuthenticationHandlerWithScheme { scheme, handler },
            default_scheme: self.default_scheme,
        }
    }
}

impl Default for AuthenticationServiceBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Handler> AuthenticationServiceBuilder<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    pub fn add_authentication_handler<H: AuthenticationHandler>(
        self,
        scheme: String,
        handler: H,
    ) -> AuthenticationServiceBuilder<(Handler, AuthenticationHandlerWithScheme<H>)> {
        AuthenticationServiceBuilder {
            handler: (
                self.handler,
                AuthenticationHandlerWithScheme { scheme, handler },
            ),
            default_scheme: self.default_scheme,
        }
    }

    pub fn set_default_scheme(self, scheme: String) -> Self {
        Self {
            default_scheme: Some(scheme),
            ..self
        }
    }

    pub fn build(self) -> Option<AuthenticationService<Handler>> {
        let Some(default_scheme) = self.default_scheme else {
            return None;
        };

        Some(AuthenticationService {
            default_scheme,
            handler: self.handler,
        })
    }
}
