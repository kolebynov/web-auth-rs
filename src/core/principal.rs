#[derive(Debug, Clone)]
pub struct Claim {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct UserPrincipal {
    pub claims: Vec<Claim>,
}

impl UserPrincipal {
    pub fn is_in_role(&self, role: &str) -> bool {
        self.claims
            .iter()
            .any(|x| x.kind == "role" && x.value == role)
    }
}
