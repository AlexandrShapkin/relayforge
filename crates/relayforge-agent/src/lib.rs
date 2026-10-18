//! Agent placeholder: no network listener and no command execution.
pub fn enabled() -> bool {
    false
}
#[cfg(test)]
mod tests {
    #[test]
    fn no_executor_enabled() {
        assert!(!super::enabled());
    }
}
