//! Errors of the command-line tools: a usage mistake (print the usage text
//! after it) or a failure.

pub enum CliError {
    Usage(String),
    Failed(String),
}

/// A usage mistake.
pub fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::Failed(message.to_owned())
    }
}

impl From<crate::Failure> for CliError {
    fn from(failure: crate::Failure) -> Self {
        Self::Failed(failure.to_string())
    }
}

impl CliError {
    /// Print the error (and `usage_text` after a usage mistake).
    pub fn report(&self, usage_text: &str) {
        match self {
            Self::Usage(message) => eprint!("error: {message}\n{usage_text}"),
            Self::Failed(message) => eprintln!("error: {message}"),
        }
    }
}
