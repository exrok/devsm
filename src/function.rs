/// Actions that a saved function can perform at runtime.
#[derive(Clone, Debug)]
pub enum FunctionAction {
    /// Restart a captured selection (task name and profile captured when function was set).
    RestartCaptured { task_name: String, profile: String },
}

/// Actions available when setting a function via keybinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetFunctionAction {
    /// Capture the current selection's task name for later restart.
    RestartCurrentSelection,
}
