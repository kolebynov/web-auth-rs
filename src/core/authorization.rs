use std::sync::Arc;

use async_trait::async_trait;

use super::{
    authentication::{AuthenticationService, CompoundAuthenticationHandler},
    http::{AuthResponse, Request},
    principal::AuthenticatedPrincipal,
};

#[async_trait]
pub trait AuthorizationRequirement: Clone + Send + Sync + 'static {
    async fn authorize(&self, principal: &mut AuthenticatedPrincipal) -> bool;
}

#[async_trait]
impl AuthorizationRequirement for () {
    async fn authorize(&self, _: &mut AuthenticatedPrincipal) -> bool {
        true
    }
}

#[async_trait]
impl<R1, R2> AuthorizationRequirement for (R1, R2)
where
    R1: AuthorizationRequirement,
    R2: AuthorizationRequirement,
{
    async fn authorize(&self, principal: &mut AuthenticatedPrincipal) -> bool {
        self.0.authorize(principal).await && self.1.authorize(principal).await
    }
}

#[derive(Clone)]
pub struct IsInRoleRequirement(pub String);

#[async_trait]
impl AuthorizationRequirement for IsInRoleRequirement {
    async fn authorize(&self, principal: &mut AuthenticatedPrincipal) -> bool {
        principal.is_in_role(&self.0)
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
        let Some(principal) = request.get_extension_mut() else {
            return Err(self.auth_service.challenge(None).await);
        };

        if !self.requirement.authorize(principal).await {
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

    pub fn require_role(
        self,
        role: String,
    ) -> AuthorizationPolicyBuilder<(Requirement, IsInRoleRequirement)> {
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
