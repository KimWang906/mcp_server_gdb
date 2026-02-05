use std::fmt::{Display, Formatter};
use std::panic::Location;

use anyhow::Error as AnyhowError;

/// Classification for machine-actionable error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Caller supplied invalid input.
    InvalidArgument,
    /// Requested resource does not exist.
    NotFound,
    /// Operation timed out.
    Timeout,
    /// System is busy; retry may succeed.
    Busy,
    /// Failed to parse or decode input/output.
    Parse,
    /// I/O failure.
    Io,
    /// Protocol or message contract violation.
    Protocol,
    /// Backend or subsystem failure (e.g. GDB).
    Backend,
    /// Unexpected internal error.
    Internal,
}

impl ErrorKind {
    /// Render the kind as a stable string for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::NotFound => "not_found",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Busy => "busy",
            ErrorKind::Parse => "parse",
            ErrorKind::Io => "io",
            ErrorKind::Protocol => "protocol",
            ErrorKind::Backend => "backend",
            ErrorKind::Internal => "internal",
        }
    }
}

/// Retry guidance for callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStatus {
    /// Retry is likely to succeed.
    Temporary,
    /// Retry is unlikely to help without changing input.
    Permanent,
    /// Retry guidance is unknown.
    Unknown,
}

impl ErrorStatus {
    /// Returns true when a retry is recommended.
    pub fn is_retryable(&self) -> bool {
        matches!(self, ErrorStatus::Temporary)
    }

    /// Render the status as a stable string for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorStatus::Temporary => "temporary",
            ErrorStatus::Permanent => "permanent",
            ErrorStatus::Unknown => "unknown",
        }
    }
}

/// Structured context key/value for error frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorField {
    /// Context key.
    pub key: &'static str,
    /// Context value.
    pub value: String,
}

impl ErrorField {
    /// Create a new context field.
    pub fn new(key: &'static str, value: impl Into<String>) -> Self {
        Self { key, value: value.into() }
    }
}

/// A single frame of error context.
#[derive(Debug, Clone)]
pub struct ErrorFrame {
    /// Operation being performed.
    pub operation: &'static str,
    /// Message describing the failure at this frame.
    pub message: String,
    /// Callsite location for this frame.
    pub location: &'static Location<'static>,
    /// Structured context fields for this frame.
    pub fields: Vec<ErrorField>,
}

impl ErrorFrame {
    /// Create a new frame with caller location.
    #[track_caller]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
            location: Location::caller(),
            fields: Vec::new(),
        }
    }

    /// Attach a structured context field.
    pub fn with_field(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.fields.push(ErrorField::new(key, value));
        self
    }
}

/// Application error with machine and human context.
#[derive(Debug)]
pub struct AppError {
    /// Machine-actionable kind.
    pub kind: ErrorKind,
    /// Retry guidance.
    pub status: ErrorStatus,
    /// Human-friendly summary.
    pub message: String,
    /// Context frames from outermost to innermost.
    pub frames: Vec<ErrorFrame>,
    /// Optional source error for debugging.
    pub source: Option<AnyhowError>,
}

impl AppError {
    /// Create a new error with a root frame.
    #[track_caller]
    pub fn new(
        kind: ErrorKind,
        status: ErrorStatus,
        operation: &'static str,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        Self {
            kind,
            status,
            message: message.clone(),
            frames: vec![ErrorFrame::new(operation, message)],
            source: None,
        }
    }

    /// Create an invalid-argument error.
    #[track_caller]
    pub fn invalid_argument(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgument, ErrorStatus::Permanent, operation, message)
    }

    /// Create a not-found error.
    #[track_caller]
    pub fn not_found(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, ErrorStatus::Permanent, operation, message)
    }

    /// Create a timeout error.
    #[track_caller]
    pub fn timeout(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, ErrorStatus::Temporary, operation, message)
    }

    /// Create a busy error.
    #[track_caller]
    pub fn busy(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Busy, ErrorStatus::Temporary, operation, message)
    }

    /// Create a parse error.
    #[track_caller]
    pub fn parse(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Parse, ErrorStatus::Permanent, operation, message)
    }

    /// Create an I/O error.
    #[track_caller]
    pub fn io(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, ErrorStatus::Unknown, operation, message)
    }

    /// Create a protocol error.
    #[track_caller]
    pub fn protocol(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, ErrorStatus::Permanent, operation, message)
    }

    /// Create a backend error.
    #[track_caller]
    pub fn backend(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Backend, ErrorStatus::Unknown, operation, message)
    }

    /// Create an internal error.
    #[track_caller]
    pub fn internal(operation: &'static str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, ErrorStatus::Unknown, operation, message)
    }

    /// Attach a source error for debugging.
    pub fn with_source(mut self, source: impl Into<AnyhowError>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Push a new frame of context.
    #[track_caller]
    pub fn with_context(mut self, operation: &'static str, message: impl Into<String>) -> Self {
        self.frames.push(ErrorFrame::new(operation, message));
        self
    }

    /// Attach a structured field to the latest frame.
    pub fn with_field(mut self, key: &'static str, value: impl Into<String>) -> Self {
        if let Some(frame) = self.frames.last_mut() {
            frame.fields.push(ErrorField::new(key, value));
        }
        self
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let operation = self
            .frames
            .last()
            .map(|frame| frame.operation)
            .unwrap_or("unknown");
        write!(
            f,
            "{}: {} (kind={}, status={})",
            operation,
            self.message,
            self.kind.as_str(),
            self.status.as_str()
        )
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|err| err.as_ref() as _)
    }
}

/// Application result type.
pub type AppResult<T> = Result<T, AppError>;

/// Result extension for adding error context.
pub trait ResultContextExt<T> {
    /// Add a context frame when returning an error.
    fn context(self, operation: &'static str, message: impl Into<String>) -> AppResult<T>;
    /// Attach a structured field to the latest error frame.
    fn field(self, key: &'static str, value: impl Into<String>) -> AppResult<T>;
}

impl<T, E> ResultContextExt<T> for Result<T, E>
where
    AppError: From<E>,
{
    #[track_caller]
    fn context(self, operation: &'static str, message: impl Into<String>) -> AppResult<T> {
        self.map_err(AppError::from)
            .map_err(|err| err.with_context(operation, message))
    }

    fn field(self, key: &'static str, value: impl Into<String>) -> AppResult<T> {
        self.map_err(AppError::from)
            .map_err(|err| err.with_field(key, value))
    }
}

impl From<rmcp::service::ServerInitializeError> for AppError {
    #[track_caller]
    fn from(error: rmcp::service::ServerInitializeError) -> Self {
        AppError::internal("rmcp.initialize", error.to_string()).with_source(error)
    }
}

impl From<std::io::Error> for AppError {
    #[track_caller]
    fn from(error: std::io::Error) -> Self {
        AppError::io("io", error.to_string())
            .with_field("io_kind", format!("{:?}", error.kind()))
            .with_source(error)
    }
}

impl From<std::num::ParseIntError> for AppError {
    #[track_caller]
    fn from(error: std::num::ParseIntError) -> Self {
        AppError::parse("parse_int", error.to_string()).with_source(error)
    }
}

impl From<serde_json::error::Error> for AppError {
    #[track_caller]
    fn from(error: serde_json::error::Error) -> Self {
        AppError::parse("parse_json", error.to_string()).with_source(error)
    }
}

impl From<anyhow::Error> for AppError {
    #[track_caller]
    fn from(error: anyhow::Error) -> Self {
        AppError::internal("anyhow", error.to_string()).with_source(error)
    }
}

impl From<tokio::task::JoinError> for AppError {
    #[track_caller]
    fn from(error: tokio::task::JoinError) -> Self {
        AppError::internal("tokio.join", error.to_string()).with_source(error)
    }
}

impl From<AppError> for rmcp::ErrorData {
    fn from(error: AppError) -> Self {
        let code = match error.kind {
            ErrorKind::InvalidArgument => rmcp::model::ErrorCode::INVALID_PARAMS,
            ErrorKind::NotFound => rmcp::model::ErrorCode::RESOURCE_NOT_FOUND,
            ErrorKind::Parse => rmcp::model::ErrorCode::PARSE_ERROR,
            ErrorKind::Protocol => rmcp::model::ErrorCode::INVALID_REQUEST,
            _ => rmcp::model::ErrorCode::INTERNAL_ERROR,
        };
        let frames = error
            .frames
            .iter()
            .map(|frame| {
                let fields = frame
                    .fields
                    .iter()
                    .map(|field| (field.key, field.value.clone()))
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "operation": frame.operation,
                    "message": frame.message,
                    "location": format!("{}:{}", frame.location.file(), frame.location.line()),
                    "fields": fields,
                })
            })
            .collect::<Vec<_>>();
        rmcp::ErrorData::new(
            code,
            error.message,
            Some(serde_json::json!({
                "kind": error.kind.as_str(),
                "status": error.status.as_str(),
                "retryable": error.status.is_retryable(),
                "frames": frames,
            })),
        )
    }
}
