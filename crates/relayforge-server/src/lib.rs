//! Coordinator placeholder: no network listener or device enrollment.
pub fn enabled() -> bool {
    false
}
#[cfg(test)]
mod tests {
    #[test]
    fn no_listener_enabled() {
        assert!(!super::enabled());
    }
}

pub mod session;
