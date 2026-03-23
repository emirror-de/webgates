//! Integration-layer error conversions and adapters.
//!
//! This module hosts conversions from external/library errors into the crate-wide
//! `Error` type, keeping the core error definitions free of downstream
//! dependencies. By isolating these mappings, we reduce afferent/efferent
//! coupling and avoid cycles with codec, hashing, and configuration modules.
//!
//! Add new conversions here when they pull in external crates or higher-level
//! modules (HTTP, storage, config). Keep core/domain errors unaware of these
//! details.

use crate::codecs::errors::{CodecOperation, CodecsError};
use crate::errors::Error;

/// Map cookie template builder validation errors into the crate-wide `Error`
/// under the codecs category.
///
/// Cookie template configuration is treated as a format/codec concern.
impl From<crate::cookie_template::CookieTemplateBuilderError> for Error {
    fn from(err: crate::cookie_template::CookieTemplateBuilderError) -> Self {
        Error::Codecs(CodecsError::codec_with_format(
            CodecOperation::Encode,
            format!("Invalid cookie template configuration: {}", err),
            Some("cookie::CookieBuilder".to_string()),
            Some("Invalid cookie settings".to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::UserFriendlyError;

    #[test]
    fn cookie_template_error_maps_to_codec_error() {
        // Construct a minimal invalid builder error via Display formatting.
        let builder_err = crate::cookie_template::CookieTemplateBuilderError::InsecureNoneSameSite;
        let mapped = Error::from(builder_err);
        match mapped {
            Error::Codecs(c) => {
                assert!(c.developer_message().contains("Invalid cookie template"));
                assert_eq!(c.severity(), crate::errors::ErrorSeverity::Error);
            }
            _ => panic!("expected codec error"),
        }
    }
}
