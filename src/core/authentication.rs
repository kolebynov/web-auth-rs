use std::future::{ready, Future, Ready};

use futures::future::OptionFuture;

use super::{
    futures::{select_seq_ok, select_seq_some, SelectSeqOk, SelectSeqSome},
    http::{AuthResponse, Request, RequestExtensions},
    principal::UserPrincipal,
};

pub enum AuthenticationError {
    NoResult,
    Fail(anyhow::Error),
}

pub type AuthenticationResult = Result<UserPrincipal, AuthenticationError>;

#[derive(Clone)]
pub struct SuccessAuthenticationResult {
    pub principal: UserPrincipal,
}

pub trait AuthenticationHandler: Send + Sync + 'static {
    type AuthFut: Future<Output = AuthenticationResult>;

    type ChallengeFut: Future<Output = AuthResponse>;

    type ForbidFut: Future<Output = AuthResponse>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut;

    fn challenge(&self) -> Self::ChallengeFut;

    fn forbid(&self) -> Self::ForbidFut;
}

pub trait SignInOutAuthenticationHandler: AuthenticationHandler {
    type SignInFut: Future<Output = AuthResponse>;

    type SignOutFut: Future<Output = AuthResponse>;

    fn sign_in(&self, user: &UserPrincipal) -> Self::SignInFut;

    fn sign_out(&self) -> Self::SignOutFut;
}

pub trait CompoundAuthenticationHandler: Send + Sync + 'static {
    type AuthFut: Future<Output = AuthenticationResult>;

    type ChallengeFut: Future<Output = Option<AuthResponse>>;

    type ForbidFut: Future<Output = Option<AuthResponse>>;

    type SignInFut: Future<Output = Option<AuthResponse>>;

    type SignOutFut: Future<Output = Option<AuthResponse>>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut;

    fn challenge(&self, scheme: &str) -> Self::ChallengeFut;

    fn forbid(&self, scheme: &str) -> Self::ForbidFut;

    fn sign_in(&self, scheme: &str, user: &UserPrincipal) -> Self::SignInFut;

    fn sign_out(&self, scheme: &str) -> Self::SignOutFut;
}

impl<H1, H2> CompoundAuthenticationHandler for (H1, H2)
where
    H1: CompoundAuthenticationHandler,
    H2: CompoundAuthenticationHandler,
{
    type AuthFut = SelectSeqOk<H1::AuthFut, H2::AuthFut>;

    type ChallengeFut = SelectSeqSome<H1::ChallengeFut, H2::ChallengeFut>;

    type ForbidFut = SelectSeqSome<H1::ForbidFut, H2::ForbidFut>;

    type SignInFut = SelectSeqSome<H1::SignInFut, H2::SignInFut>;

    type SignOutFut = SelectSeqSome<H1::SignOutFut, H2::SignOutFut>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut {
        select_seq_ok(self.0.authenticate(request), self.1.authenticate(request))
    }

    fn challenge(&self, scheme: &str) -> Self::ChallengeFut {
        select_seq_some(self.0.challenge(scheme), self.1.challenge(scheme))
    }

    fn forbid(&self, scheme: &str) -> Self::ForbidFut {
        select_seq_some(self.0.forbid(scheme), self.1.forbid(scheme))
    }

    fn sign_in(&self, scheme: &str, user: &UserPrincipal) -> Self::SignInFut {
        select_seq_some(self.0.sign_in(scheme, user), self.1.sign_in(scheme, user))
    }

    fn sign_out(&self, scheme: &str) -> Self::SignOutFut {
        select_seq_some(self.0.sign_out(scheme), self.1.sign_out(scheme))
    }
}

pub struct AuthenticationHandlerWithScheme<Handler: AuthenticationHandler> {
    pub scheme: String,
    pub handler: Handler,
}

impl<H> CompoundAuthenticationHandler for AuthenticationHandlerWithScheme<H>
where
    H: AuthenticationHandler,
{
    type AuthFut = H::AuthFut;

    type ChallengeFut = OptionFuture<H::ChallengeFut>;

    type ForbidFut = OptionFuture<H::ForbidFut>;

    type SignInFut = Ready<Option<AuthResponse>>;

    type SignOutFut = Ready<Option<AuthResponse>>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut {
        self.handler.authenticate(request)
    }

    fn challenge(&self, scheme: &str) -> Self::ChallengeFut {
        if scheme == self.scheme {
            Some(self.handler.challenge()).into()
        } else {
            None.into()
        }
    }

    fn forbid(&self, scheme: &str) -> Self::ForbidFut {
        if scheme == self.scheme {
            Some(self.handler.forbid()).into()
        } else {
            None.into()
        }
    }

    fn sign_in(&self, _: &str, _: &UserPrincipal) -> Self::SignInFut {
        ready(None)
    }

    fn sign_out(&self, _: &str) -> Self::SignOutFut {
        ready(None)
    }
}

pub struct SignInOutAuthenticationHandlerWithScheme<Handler: SignInOutAuthenticationHandler> {
    pub scheme: String,
    pub handler: Handler,
}

impl<H> CompoundAuthenticationHandler for SignInOutAuthenticationHandlerWithScheme<H>
where
    H: SignInOutAuthenticationHandler,
{
    type AuthFut = H::AuthFut;

    type ChallengeFut = OptionFuture<H::ChallengeFut>;

    type ForbidFut = OptionFuture<H::ForbidFut>;

    type SignInFut = OptionFuture<H::SignInFut>;

    type SignOutFut = OptionFuture<H::SignOutFut>;

    fn authenticate(&self, request: &mut impl Request) -> Self::AuthFut {
        self.handler.authenticate(request)
    }

    fn challenge(&self, scheme: &str) -> Self::ChallengeFut {
        if scheme == self.scheme {
            Some(self.handler.challenge()).into()
        } else {
            None.into()
        }
    }

    fn forbid(&self, scheme: &str) -> Self::ForbidFut {
        if scheme == self.scheme {
            Some(self.handler.forbid()).into()
        } else {
            None.into()
        }
    }

    fn sign_in(&self, scheme: &str, user: &UserPrincipal) -> Self::SignInFut {
        if scheme == self.scheme {
            Some(self.handler.sign_in(user)).into()
        } else {
            None.into()
        }
    }

    fn sign_out(&self, scheme: &str) -> Self::SignOutFut {
        if scheme == self.scheme {
            Some(self.handler.sign_out()).into()
        } else {
            None.into()
        }
    }
}

pub struct AuthenticationService<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    handler: Handler,
    default_scheme: String,
}

impl<Handler> AuthenticationService<Handler>
where
    Handler: CompoundAuthenticationHandler,
{
    pub async fn authenticate(&self, request: &mut impl Request) {
        let result = self.handler.authenticate(request).await;
        if let Ok(principal) = result {
            request
                .get_extensions_mut()
                .insert(SuccessAuthenticationResult { principal });
        }
    }

    pub async fn challenge(&self, scheme: Option<&str>) -> AuthResponse {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        self.handler
            .challenge(scheme)
            .await
            .unwrap_or_else(|| panic!("Scheme {scheme} is not configured"))
    }

    pub async fn forbid(&self, scheme: Option<&str>) -> AuthResponse {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        self.handler
            .forbid(scheme)
            .await
            .unwrap_or_else(|| panic!("Scheme {scheme} is not configured"))
    }

    pub async fn sign_in(&self, scheme: Option<&str>, user: &UserPrincipal) -> AuthResponse {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        self.handler
            .sign_in(scheme, user)
            .await
            .unwrap_or_else(|| panic!("Scheme {scheme} is not configured or it doesn't support sign-in/sign-out"))
    }

    pub async fn sign_out(&self, scheme: Option<&str>) -> AuthResponse {
        let scheme = scheme.unwrap_or(&self.default_scheme);
        self.handler
            .sign_out(scheme)
            .await
            .unwrap_or_else(|| panic!("Scheme {scheme} is not configured or it doesn't support sign-in/sign-out"))
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

    pub fn add_sign_in_out_authentication_handler<H: SignInOutAuthenticationHandler>(
        self,
        scheme: String,
        handler: H,
    ) -> AuthenticationServiceBuilder<SignInOutAuthenticationHandlerWithScheme<H>> {
        AuthenticationServiceBuilder {
            handler: SignInOutAuthenticationHandlerWithScheme { scheme, handler },
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
            handler: (self.handler, AuthenticationHandlerWithScheme { scheme, handler }),
            default_scheme: self.default_scheme,
        }
    }

    pub fn add_sign_in_out_authentication_handler<H: SignInOutAuthenticationHandler>(
        self,
        scheme: String,
        handler: H,
    ) -> AuthenticationServiceBuilder<(Handler, SignInOutAuthenticationHandlerWithScheme<H>)> {
        AuthenticationServiceBuilder {
            handler: (
                self.handler,
                SignInOutAuthenticationHandlerWithScheme { scheme, handler },
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
