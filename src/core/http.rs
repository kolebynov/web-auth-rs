use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};

pub trait RequestExtensions {
    fn get<T: Send + Sync + 'static>(&self) -> Option<&T>;

    fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T>;

    fn insert<T: Send + Sync + 'static>(&mut self, ext: T) -> Option<T>;
}

pub trait Request {
    type RequestExtensions: RequestExtensions;

    type RequestExtensionsDeref<'a>: Deref<Target = Self::RequestExtensions> + 'a
    where
        Self: 'a;

    type RequestExtensionsDerefMut<'a>: DerefMut<Target = Self::RequestExtensions> + 'a
    where
        Self: 'a;

    fn get_uri(&self) -> &Uri;

    fn get_header(&self, header: &HeaderName) -> Option<&HeaderValue>;

    fn get_extensions(&self) -> Self::RequestExtensionsDeref<'_>;

    fn get_extensions_mut(&mut self) -> Self::RequestExtensionsDerefMut<'_>;
}

#[derive(Debug)]
pub struct AuthResponse {
    pub status_code: StatusCode,
    pub headers: HeaderMap,
}

impl Display for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
