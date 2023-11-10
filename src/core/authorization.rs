use std::{
    future::{ready, Ready},
    sync::Arc,
};

use futures::{
    future::{join, Join},
    Future,
};

use super::{
    authentication::{AuthenticationService, CompoundAuthenticationHandler, SuccessAuthenticationResult},
    futures::{merge_bool_and, MergeBoolAnd},
    http::{AuthResponse, Request, RequestExtensions},
    principal::UserPrincipal,
};

pub trait AuthorizationRequirement: Clone + Send + Sync + 'static {
    type AuthorizeFut: Future<Output = bool>;

    fn authorize(&self, principal: &mut UserPrincipal) -> Self::AuthorizeFut;
}

impl AuthorizationRequirement for () {
    type AuthorizeFut = Ready<bool>;

    fn authorize(&self, _: &mut UserPrincipal) -> Self::AuthorizeFut {
        ready(true)
    }
}

impl<R1, R2> AuthorizationRequirement for (R1, R2)
where
    R1: AuthorizationRequirement,
    R2: AuthorizationRequirement,
{
    type AuthorizeFut = MergeBoolAnd<Join<R1::AuthorizeFut, R2::AuthorizeFut>>;

    fn authorize(&self, principal: &mut UserPrincipal) -> Self::AuthorizeFut {
        merge_bool_and(join(self.0.authorize(principal), self.1.authorize(principal)))
    }
}

#[derive(Clone)]
pub struct IsInRoleRequirement(pub String);

impl AuthorizationRequirement for IsInRoleRequirement {
    type AuthorizeFut = Ready<bool>;

    fn authorize(&self, principal: &mut UserPrincipal) -> Self::AuthorizeFut {
        ready(principal.is_in_role(&self.0))
    }
}

pub struct AuthorizationPolicy<Handler, Requirement = ()>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    auth_service: Arc<AuthenticationService<Handler>>,
    requirement: Requirement,
}

impl<Handler, Requirement> AuthorizationPolicy<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    pub async fn authorize(&self, request: &mut impl Request) -> Result<(), AuthResponse> {
        let mut extensions = request.get_extensions_mut();
        let Some(auth_result) = extensions.get_mut::<SuccessAuthenticationResult>() else {
            return Err(self.auth_service.challenge(None).await);
        };

        if !self.requirement.authorize(&mut auth_result.principal).await {
            return Err(self.auth_service.forbid(None).await);
        }

        Ok(())
    }
}

impl<Handler, Requirement> Clone for AuthorizationPolicy<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self {
            auth_service: self.auth_service.clone(),
            requirement: self.requirement.clone(),
        }
    }
}

pub struct AuthorizationPolicyBuilder<Requirement>
where
    Requirement: AuthorizationRequirement,
{
    requirement: Requirement,
}

impl AuthorizationPolicyBuilder<()> {
    pub fn new() -> Self {
        Self { requirement: () }
    }
}

impl<Requirement> AuthorizationPolicyBuilder<Requirement>
where
    Requirement: AuthorizationRequirement,
{
    pub fn add_requirement<R: AuthorizationRequirement>(
        self,
        requirement: R,
    ) -> AuthorizationPolicyBuilder<(Requirement, R)> {
        AuthorizationPolicyBuilder {
            requirement: (self.requirement, requirement),
        }
    }

    pub fn require_role(self, role: String) -> AuthorizationPolicyBuilder<(Requirement, IsInRoleRequirement)> {
        self.add_requirement(IsInRoleRequirement(role))
    }

    pub fn build<Handler: CompoundAuthenticationHandler>(
        self,
        auth_service: Arc<AuthenticationService<Handler>>,
    ) -> AuthorizationPolicy<Handler, Requirement> {
        AuthorizationPolicy {
            auth_service,
            requirement: self.requirement,
        }
    }
}

impl Default for AuthorizationPolicyBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}
