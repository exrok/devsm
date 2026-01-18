use std::ops::Range;

use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelStyle {
    Primary,
    Secondary,
}

#[derive(Clone, Debug)]
pub struct DiagnosticLabel {
    pub style: LabelStyle,
    pub span: Range<usize>,
    pub message: String,
}

impl DiagnosticLabel {
    pub fn primary(span: Range<usize>) -> Self {
        Self { style: LabelStyle::Primary, span, message: String::new() }
    }

    pub fn secondary(span: Range<usize>) -> Self {
        Self { style: LabelStyle::Secondary, span, message: String::new() }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
    pub labels: Vec<DiagnosticLabel>,
    pub notes: Vec<String>,
}

impl Diagnostic {
    pub fn error() -> Self {
        Self { level: DiagnosticLevel::Error, message: String::new(), labels: Vec::new(), notes: Vec::new() }
    }

    pub fn warning() -> Self {
        Self { level: DiagnosticLevel::Warning, message: String::new(), labels: Vec::new(), notes: Vec::new() }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub fn with_label(mut self, label: DiagnosticLabel) -> Self {
        self.labels.push(label);
        self
    }

    pub fn with_labels(mut self, labels: Vec<DiagnosticLabel>) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }
}

pub fn render_diagnostic(file_name: &str, content: &str, diagnostic: &Diagnostic) -> String {
    let level = match diagnostic.level {
        DiagnosticLevel::Error => Level::ERROR,
        DiagnosticLevel::Warning => Level::WARNING,
    };

    let mut snippet = Snippet::source(content).path(file_name);
    for label in &diagnostic.labels {
        let kind = match label.style {
            LabelStyle::Primary => AnnotationKind::Primary,
            LabelStyle::Secondary => AnnotationKind::Context,
        };
        let annotation = if label.message.is_empty() {
            kind.span(label.span.clone())
        } else {
            kind.span(label.span.clone()).label(&label.message)
        };
        snippet = snippet.annotation(annotation);
    }

    let mut groups: Vec<Group> = Vec::new();

    let title = level.primary_title(&diagnostic.message);
    groups.push(title.element(snippet));

    for note in &diagnostic.notes {
        groups.push(Group::with_title(Level::NOTE.secondary_title(note)));
    }

    let renderer = Renderer::styled();
    renderer.render(&groups).to_string()
}

pub fn emit_diagnostic(file_name: &str, content: &str, diagnostic: &Diagnostic) {
    eprint!("{}", render_diagnostic(file_name, content, diagnostic));
}

pub fn toml_error_to_diagnostic(err: &toml_spanner::Error) -> Diagnostic {
    use toml_spanner::ErrorKind;

    let span: Range<usize> = err.span.into();

    match &err.kind {
        ErrorKind::UnexpectedEof => {
            Diagnostic::error().with_message("unexpected end of file").with_label(DiagnosticLabel::primary(span))
        }

        ErrorKind::FileTooLarge => Diagnostic::error()
            .with_message("file is too large (maximum 4GiB)")
            .with_label(DiagnosticLabel::primary(span)),

        ErrorKind::InvalidCharInString(c) => {
            Diagnostic::error().with_message("invalid character in string").with_label(
                DiagnosticLabel::primary(span).with_message(format!("invalid character '{}'", escape_char(*c))),
            )
        }

        ErrorKind::InvalidEscape(c) => Diagnostic::error()
            .with_message("invalid escape character")
            .with_label(DiagnosticLabel::primary(span).with_message(format!("invalid escape '{}'", escape_char(*c)))),

        ErrorKind::InvalidHexEscape(c) => Diagnostic::error().with_message("invalid hex escape").with_label(
            DiagnosticLabel::primary(span).with_message(format!("invalid hex escape '{}'", escape_char(*c))),
        ),

        ErrorKind::InvalidEscapeValue(_) => Diagnostic::error()
            .with_message("invalid escape value")
            .with_label(DiagnosticLabel::primary(span).with_message("invalid escape value")),

        ErrorKind::Unexpected(c) => Diagnostic::error()
            .with_message("unexpected character")
            .with_label(DiagnosticLabel::primary(span).with_message(format!("unexpected '{}'", escape_char(*c)))),

        ErrorKind::UnterminatedString => Diagnostic::error()
            .with_message("unterminated string")
            .with_label(DiagnosticLabel::primary(span).with_message("eof reached before string terminator")),

        ErrorKind::InvalidNumber => Diagnostic::error()
            .with_message("invalid number")
            .with_label(DiagnosticLabel::primary(span).with_message("unable to parse number")),

        ErrorKind::OutOfRange(kind) => Diagnostic::error()
            .with_message(format!("number is out of range of '{kind}'"))
            .with_label(DiagnosticLabel::primary(span)),

        ErrorKind::Wanted { expected, .. } => Diagnostic::error()
            .with_message(format!("expected {expected}"))
            .with_label(DiagnosticLabel::primary(span).with_message(format!("expected {expected}"))),

        ErrorKind::DuplicateTable { name, first } => {
            let first_span: Range<usize> = (*first).into();
            Diagnostic::error().with_message(format!("redefinition of table `{name}`")).with_labels(vec![
                DiagnosticLabel::secondary(first_span).with_message("first table instance"),
                DiagnosticLabel::primary(span).with_message("duplicate table"),
            ])
        }

        ErrorKind::DuplicateKey { key, first } => {
            let first_span: Range<usize> = (*first).into();
            Diagnostic::error().with_message(format!("duplicate key: `{key}`")).with_labels(vec![
                DiagnosticLabel::secondary(first_span).with_message("first key instance"),
                DiagnosticLabel::primary(span).with_message("duplicate key"),
            ])
        }

        ErrorKind::RedefineAsArray => {
            Diagnostic::error().with_message("table redefined as array").with_label(DiagnosticLabel::primary(span))
        }

        ErrorKind::MultilineStringKey => Diagnostic::error()
            .with_message("multiline strings are not allowed for key")
            .with_label(DiagnosticLabel::primary(span).with_message("multiline keys are not allowed")),

        ErrorKind::Custom(message) => {
            Diagnostic::error().with_message(message.to_string()).with_label(DiagnosticLabel::primary(span))
        }

        ErrorKind::DottedKeyInvalidType { first } => {
            let first_span: Range<usize> = (*first).into();
            Diagnostic::error().with_message("dotted key attempted to extend non-table type").with_labels(vec![
                DiagnosticLabel::primary(span).with_message("attempted to extend table here"),
                DiagnosticLabel::secondary(first_span).with_message("non-table"),
            ])
        }

        ErrorKind::UnexpectedKeys { keys, expected } => {
            let mut labels: Vec<_> = keys.iter().map(|(_, s)| DiagnosticLabel::secondary((*s).into())).collect();
            if !labels.is_empty() {
                labels[0].style = LabelStyle::Primary;
            }
            Diagnostic::error()
                .with_message(format!("found {} unexpected keys, expected: {expected:?}", keys.len()))
                .with_labels(labels)
        }

        ErrorKind::UnquotedString => Diagnostic::error()
            .with_message("unquoted string")
            .with_label(DiagnosticLabel::primary(span).with_message("string is not quoted")),

        ErrorKind::MissingField(field) => Diagnostic::error()
            .with_message(format!("missing field '{field}'"))
            .with_label(DiagnosticLabel::primary(span).with_message("table with missing field")),

        ErrorKind::Deprecated { new, .. } => Diagnostic::error()
            .with_message(format!("deprecated field encountered, '{new}' should be used instead"))
            .with_label(DiagnosticLabel::primary(span).with_message("deprecated field")),

        ErrorKind::UnexpectedValue { expected, .. } => Diagnostic::error()
            .with_message(format!("expected '{expected:?}'"))
            .with_label(DiagnosticLabel::primary(span).with_message("unexpected value")),
    }
}

fn escape_char(c: char) -> String {
    if c.is_whitespace() { c.escape_default().to_string() } else { c.to_string() }
}
