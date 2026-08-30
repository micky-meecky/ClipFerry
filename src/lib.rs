pub mod app_settings;
pub mod clipboard;
pub mod device_store;
pub mod discovery;
pub mod pairing;
pub mod security;
pub mod tray;

pub const APP_NAME: &str = "ClipFerry";

#[must_use]
pub const fn validation_banner() -> &'static str {
    "ClipFerry technical validation"
}

#[cfg(test)]
mod tests {
    use super::{APP_NAME, validation_banner};

    #[test]
    fn validation_banner_identifies_the_application() {
        assert!(validation_banner().starts_with(APP_NAME));
    }
}
