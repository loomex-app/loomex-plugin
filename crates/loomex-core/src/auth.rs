use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthIdentity {
    User { user_id: String },
    ApiKey { api_key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub organization_id: String,
    pub identity: AuthIdentity,
    pub management_token_present: bool,
}

impl AuthContext {
    pub fn validate_for_management(&self) -> CoreResult<()> {
        if self.organization_id.trim().is_empty() {
            return Err(CoreError::new(
                "MISSING_ORGANIZATION",
                "organization_id is required",
            ));
        }
        if !self.management_token_present {
            return Err(CoreError::new(
                "MISSING_MANAGEMENT_TOKEN",
                "management token is required",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_auth_requires_token() {
        let auth = AuthContext {
            organization_id: "org_123".to_string(),
            identity: AuthIdentity::User {
                user_id: "user_123".to_string(),
            },
            management_token_present: false,
        };

        assert_eq!(
            "MISSING_MANAGEMENT_TOKEN",
            auth.validate_for_management().unwrap_err().code
        );
    }
}
