//! Input rules applied at more than one entry point.
//!
//! Rules that belong to a single handler stay with that handler; what lives
//! here is the shape a value must have wherever it enters the application, so
//! two callers cannot drift into enforcing different things about the same
//! kind of input.

use crate::error::AppError;

/// RFC 5321's maximum forward path, which is also the widest column any store
/// downstream is likely to have.
const EMAIL_MAX_LENGTH: usize = 320;

/// Bounds and shape-checks an email address.
///
/// This is deliberately a shape check: whether an address exists is something
/// only delivery can answer, and a stricter grammar would turn away valid
/// addresses. What it does guarantee is that the value stays inert in a
/// component that gives whitespace structural meaning — an SMTP header, a log
/// line — because control characters and spaces are refused outright. An
/// address carrying a CRLF would otherwise inject a header of the attacker's
/// choosing into any message built from it.
pub fn email(address: &str) -> Result<(), AppError> {
    let Some((local, domain)) = address.split_once('@') else {
        return Err(invalid_email());
    };
    let well_formed = address.len() <= EMAIL_MAX_LENGTH
        && !address
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        && !local.is_empty()
        // `split_once` stops at the first `@`, so this is what holds an
        // address to exactly one of them.
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.');
    well_formed.then_some(()).ok_or_else(invalid_email)
}

/// One message for every way an address can fail, so a caller probing this
/// endpoint learns nothing about which rule it tripped.
fn invalid_email() -> AppError {
    AppError::BadRequest("a valid email is required".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_addresses() {
        for address in [
            "person@example.com",
            "person+tag@example.co.uk",
            "first.last@mail.example.com",
        ] {
            assert!(email(address).is_ok(), "{address:?} should be accepted");
        }
    }

    #[test]
    fn rejects_malformed_addresses() {
        for address in [
            "",
            "not-email",
            "@example.com",
            "person@",
            // No dot in the domain: a bare host is not a deliverable address.
            "person@localhost",
            "person@.com",
            "person@example.",
            // Two `@` leave it ambiguous which side is the domain.
            "person@evil.test@example.com",
        ] {
            assert!(email(address).is_err(), "{address:?} should be rejected");
        }
    }

    /// The case this validator exists for. Each of these is well formed either
    /// side of the injected run, so a shape-only check passes it through — and
    /// a worker rendering it into an SMTP header would emit the smuggled
    /// header as its own.
    #[test]
    fn rejects_addresses_carrying_control_characters_or_spaces() {
        for address in [
            "person\r\nBcc: attacker@example.com",
            "person\nBcc: attacker@example.com",
            "person\0@example.com",
            "person name@example.com",
            "person@exam ple.com",
            "person@example.com\r\n",
        ] {
            assert!(email(address).is_err(), "{address:?} should be rejected");
        }
    }

    #[test]
    fn bounds_the_length() {
        let local = "a".repeat(EMAIL_MAX_LENGTH);
        assert!(email(&format!("{local}@example.com")).is_err());
        assert!(email(&format!("{}@example.com", "a".repeat(8))).is_ok());
    }
}
