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
    let mut labels = Vec::new();
    if let Some((span, name)) = err.primary_label() {
        let mut label = DiagnosticLabel::primary(span.range());
        if name.is_empty() {
            label = label.with_message(name);
        }
        labels.push(label);
    }
    if let Some((span, name)) = err.secondary_label() {
        let mut label = DiagnosticLabel::secondary(span.range());
        if name.is_empty() {
            label = label.with_message(name);
        }
        labels.push(label);
    }
    Diagnostic { level: DiagnosticLevel::Error, message: err.message(""), labels, notes: Vec::new() }
}
