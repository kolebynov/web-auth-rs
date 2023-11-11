use std::collections::HashMap;

pub mod claim_types {
    pub const ROLE: &str = "role";
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaimPlainValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl ClaimPlainValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ClaimPlainValue::String(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ClaimPlainValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ClaimPlainValue::Float(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ClaimPlainValue::Bool(v) => Some(*v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaimValue {
    PlainValue(ClaimPlainValue),
    Array(Vec<ClaimPlainValue>),
}

struct ClaimValueIter<'a> {
    value: &'a ClaimValue,
    index: usize,
}

impl<'a> ClaimValueIter<'a> {
    fn new(value: &'a ClaimValue) -> Self {
        ClaimValueIter { value, index: 0 }
    }
}

impl<'a> Iterator for ClaimValueIter<'a> {
    type Item = &'a ClaimPlainValue;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match self.value {
            ClaimValue::PlainValue(plain_value) if self.index == 0 => Some(plain_value),
            ClaimValue::Array(arr) => arr.get(self.index),
            _ => None,
        };

        self.index += 1;
        result
    }
}

impl ClaimValue {
    pub fn iter(&self) -> impl Iterator<Item = &ClaimPlainValue> {
        ClaimValueIter::new(self)
    }
}

#[derive(Debug, Clone)]
pub struct UserPrincipal {
    pub(crate) claims: HashMap<String, ClaimValue>,
}

impl UserPrincipal {
    pub fn is_in_role(&self, role: &str) -> bool {
        self.claim(claim_types::ROLE)
            .map(|c| c.iter().any(|v| v.as_str().map(|s| s == role).unwrap_or(false)))
            .unwrap_or(false)
    }

    pub fn claim(&self, claim_type: &str) -> Option<&ClaimValue> {
        self.claims.get(claim_type)
    }

    pub fn claims(&self) -> impl Iterator<Item = (&String, &ClaimValue)> {
        self.claims.iter()
    }
}
