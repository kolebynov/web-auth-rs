use std::sync::Arc;

use async_trait::async_trait;

use super::{
    authentication::{AuthenticationService, CompoundAuthenticationHandler},
    http::{Request, Response},
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

pub struct AuthorizationPolicy<Handler, Requirement = ()> {
    auth_service: Arc<AuthenticationService<Handler>>,
    requirement: Requirement,
}

impl<Handler> AuthorizationPolicy<Handler, ()>
where
    Handler: CompoundAuthenticationHandler,
{
    pub fn new(auth_service: Arc<AuthenticationService<Handler>>) -> Self {
        Self {
            auth_service,
            requirement: (),
        }
    }
}

impl<Handler, Requirement> AuthorizationPolicy<Handler, Requirement>
where
    Handler: CompoundAuthenticationHandler,
    Requirement: AuthorizationRequirement,
{
    pub fn add_requirement<R: AuthorizationRequirement>(
        self,
        requirement: R,
    ) -> AuthorizationPolicy<Handler, (Requirement, R)> {
        AuthorizationPolicy {
            auth_service: self.auth_service,
            requirement: (self.requirement, requirement),
        }
    }

    pub async fn authorize<Resp: Response>(&self, request: &mut impl Request) -> Result<(), Resp> {
        let Some(principal) = request.get_extension_mut() else {
            let mut challenge_response = Resp::default();
            self.auth_service
                .challenge(None, &mut challenge_response)
                .await;
            return Err(challenge_response);
        };

        if !self.requirement.authorize(principal).await {
            let mut forbid_response = Resp::default();
            self.auth_service.forbid(None, &mut forbid_response).await;
            return Err(forbid_response);
        }

        Ok(())
    }
}

impl<Handler, Requirement> Clone for AuthorizationPolicy<Handler, Requirement>
where
    Requirement: AuthorizationRequirement,
{
    fn clone(&self) -> Self {
        Self {
            auth_service: self.auth_service.clone(),
            requirement: self.requirement.clone(),
        }
    }
}
