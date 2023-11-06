use http::{
    header::{AsHeaderName, IntoHeaderName},
    HeaderValue, StatusCode, Uri,
};

pub trait Request: Send {
    fn get_uri(&self) -> &Uri;

    fn get_header(&self, header: impl AsHeaderName) -> Option<&HeaderValue>;

    fn set_extension<T: Send + Sync + 'static>(&mut self, ext: T) -> Option<T>;

    fn get_extension<T: Send + Sync + 'static>(&self) -> Option<&T>;

    fn get_extension_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T>;
}

pub trait Response: Send + Default {
    fn set_status_code(&mut self, status_code: StatusCode);

    fn set_header(&mut self, header: impl IntoHeaderName, value: HeaderValue);
}
