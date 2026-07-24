#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new(secrets: Vec<String>) -> Self {
        Self { secrets }
    }

    pub fn redact(&self, input: &str) -> String {
        let redacted = self
            .secrets
            .iter()
            .fold(input.to_string(), |current, secret| {
                if secret.is_empty() {
                    current
                } else {
                    current.replace(secret, "[REDACTED]")
                }
            });
        redact_token_assignments(&redacted)
    }
}

fn redact_token_assignments(input: &str) -> String {
    input
        .split_whitespace()
        .map(|part| {
            if looks_like_token_assignment(part) {
                let separator = if part.contains('=') { '=' } else { ':' };
                let key = part
                    .split_once(separator)
                    .map(|(key, _)| key)
                    .unwrap_or(part);
                format!("{key}{separator}[REDACTED]")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_token_assignment(part: &str) -> bool {
    let Some((key, value)) = part.split_once('=').or_else(|| part.split_once(':')) else {
        return false;
    };
    let normalized = key.trim().to_ascii_lowercase();
    !value.trim().is_empty()
        && matches!(
            normalized.as_str(),
            "token" | "access_token" | "management_token" | "stream_token" | "authorization"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_configured_secret_values() {
        let redactor = Redactor::new(vec!["token_123".to_string()]);
        assert_eq!(
            "Authorization: [REDACTED]",
            redactor.redact("Authorization: token_123")
        );
    }

    #[test]
    fn token_not_printed_in_logs() {
        let redactor = Redactor::new(vec![
            "management_secret".to_string(),
            "stream_secret".to_string(),
        ]);
        let line = "management_token=management_secret stream_token=stream_secret status=ok";

        let redacted = redactor.redact(line);

        assert!(!redacted.contains("management_secret"));
        assert!(!redacted.contains("stream_secret"));
        assert_eq!(
            "management_token=[REDACTED] stream_token=[REDACTED] status=ok",
            redacted
        );
    }
}
