use std::{
    fmt::{self, Display, Write},
    hash::{BuildHasher, Hasher},
    str::FromStr,
};

use extui::event::{KeyCode, KeyEvent, KeyModifiers};
use foldhash::quality::RandomState;
use hashbrown::HashTable;

use crate::function::SetFunctionAction;

/// Compact representation of a key input event.
/// Lower 32 bits: key code (char value or special key)
/// Upper 32 bits: modifiers (CONTROL, ALT, etc.)
#[derive(Eq, PartialEq, Clone, Copy, Hash, Ord, PartialOrd, Debug)]
pub struct InputEvent(pub u64);

const SPECIAL_KEY_MASK: u64 = 0xC0_00_00_00;

macro_rules! named_keys_mapping {
    ($($keycode_name: ident => $name: literal $(| $alt_name: literal)*),* $(,)?) => {
        #[repr(u8)]
        enum __NamedKey {
            $($keycode_name,)*
            __Last
        }

        fn named_key_code_to_raw(key_code: KeyCode) -> Option<u64> {
            Some(match key_code {
                $(KeyCode::$keycode_name =>
                  SPECIAL_KEY_MASK|(__NamedKey::$keycode_name as u64),)*
                _ => return None
            })
        }

        impl InputEvent {
            fn named_key(self) -> Option<&'static str> {
                let raw = self.0;
                if raw & SPECIAL_KEY_MASK != SPECIAL_KEY_MASK {
                    return None;
                }
                if (raw & 0xff_ff_ff) >= __NamedKey::__Last as u64 {
                    return None;
                }
                let rv = unsafe { std::mem::transmute::<u8, __NamedKey>(raw as u8) };
                match rv {
                    $(__NamedKey::$keycode_name => Some($name),)*
                    _ => None
                }
            }
        }

        fn parse_named_key_to_raw(name: &str) -> Option<u64> {
            Some(match name {
                $($name $(| $alt_name)* =>
                  SPECIAL_KEY_MASK|(__NamedKey::$keycode_name as u64),)*
                _ => return None
            })
        }
    };
}

impl InputEvent {
    pub fn as_char(self) -> Option<char> {
        if self.0 & SPECIAL_KEY_MASK == SPECIAL_KEY_MASK {
            return None;
        }
        char::from_u32(self.0 as u32)
    }

    fn modifiers(self) -> KeyModifiers {
        KeyModifiers::from_bits_truncate((self.0 >> 32) as u8)
    }
}

named_keys_mapping! {
    Backspace => "BKSP" | "BACKSPACE",
    Enter => "ENTER" | "RETURN" | "\n" | "\r",
    Left => "LEFT",
    Right => "RIGHT",
    Up => "UP",
    Down => "DOWN",
    Home => "HOME",
    End => "END",
    PageDown => "PGDN" | "PAGE_DOWN",
    PageUp => "PGUP" | "PAGE_UP",
    Tab => "TAB",
    BackTab => "BKTAB" | "BACK_TAB",
    Delete => "DEL" | "DELETE",
    Insert => "INS" | "INSERT",
    Null => "NULL",
    Esc => "ESC" | "ESCAPE",
    CapsLock => "CAPS" | "CAPS_LOCK",
    ScrollLock => "SCRLK" | "SCROLL_LOCK",
    PrintScreen => "PRTSC" | "PRINT_SCREEN",
    NumLock => "NUM_LOCK",
    Pause => "PAUSE",
    Menu => "MENU",
    KeypadBegin => "KEYPAD_BEGIN"
}

impl Display for InputEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.modifiers().contains(KeyModifiers::CONTROL) {
            f.write_str("C-")?;
        }
        if self.modifiers().contains(KeyModifiers::ALT) {
            f.write_str("A-")?;
        }
        if let Some(name) = self.named_key() {
            f.write_str(name)
        } else if let Some(ch) = self.as_char() {
            if ch == ' ' { f.write_str("SPACE") } else { f.write_char(ch) }
        } else {
            f.write_str("UNKNOWN")
        }
    }
}

impl From<KeyEvent> for InputEvent {
    fn from(value: KeyEvent) -> Self {
        let mut base = match value.code {
            KeyCode::Char(ch) => ch as u64,
            named_key => named_key_code_to_raw(named_key).unwrap_or(0xff_ff_ff_ff),
        };
        base |= (value.modifiers.difference(KeyModifiers::SHIFT).bits() as u64) << 32;
        InputEvent(base)
    }
}

impl FromStr for InputEvent {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == " " {
            return Err("Use 'SPACE' instead of ' ' for space key".to_string());
        }

        let mut base = KeyModifiers::empty();
        let mut rem = input;
        while let Some((prefix, rest)) = rem.split_once('-') {
            rem = rest;
            match prefix {
                "C" | "Ctrl" => base |= KeyModifiers::CONTROL,
                "Shift" => base |= KeyModifiers::SHIFT,
                "A" | "Alt" | "M" | "Meta" => base |= KeyModifiers::ALT,
                _ => return Err(format!("Unknown modifier: `{prefix}` in binding `{input}`")),
            }
        }
        let raw_base = (base.bits() as u64) << 32;
        if let Some(named_key) = parse_named_key_to_raw(rem) {
            Ok(InputEvent(raw_base | named_key))
        } else if rem == "SPACE" {
            Ok(InputEvent(raw_base | (' ' as u64)))
        } else if rem.len() == 1 {
            Ok(InputEvent(raw_base | (rem.as_bytes()[0] as u64)))
        } else {
            Err(format!("Unknown key: `{rem}` in binding `{input}`"))
        }
    }
}

/// Commands that can be triggered by keybindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Quit,
    SelectNext,
    SelectPrev,
    FocusPrimary,
    FocusSecondary,
    RestartTask,
    TerminateTask,
    LaunchTask,
    LaunchTestFilter,
    StartGroup,
    StartSelection,
    SearchLogs,
    LogModeAll,
    LogModeSelected,
    LogModeHybrid,
    JumpToOldestLogs,
    JumpToNewestLogs,
    LogScrollUp,
    LogScrollDown,
    ToggleHelp,
    HelpScrollUp,
    HelpScrollDown,
    ToggleViewMode,
    ToggleTaskTree,
    OverlayCancel,
    OverlayConfirm,
    RefreshConfig,
    /// Rerun the last test group.
    RerunTestGroup,
    /// Narrow the test group by removing passed tests.
    NarrowTestGroup,
    /// Jump to next failure in the test group.
    NextFailInTestGroup,
    /// Jump to previous failure in the test group.
    PrevFailInTestGroup,
    /// Call a saved function by name.
    CallFunction(Box<str>),
    /// Set a saved function to capture current selection.
    SetFunction {
        name: Box<str>,
        action: SetFunctionAction,
    },
}

impl FromStr for Command {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Quit" => Command::Quit,
            "SelectNext" => Command::SelectNext,
            "SelectPrev" => Command::SelectPrev,
            "FocusPrimary" => Command::FocusPrimary,
            "FocusSecondary" => Command::FocusSecondary,
            "RestartTask" => Command::RestartTask,
            "TerminateTask" => Command::TerminateTask,
            "LaunchTask" => Command::LaunchTask,
            "LaunchTestFilter" => Command::LaunchTestFilter,
            "StartGroup" => Command::StartGroup,
            "SelectProfile" => Command::StartSelection,
            "SearchLogs" => Command::SearchLogs,
            "LogModeAll" => Command::LogModeAll,
            "LogModeSelected" => Command::LogModeSelected,
            "LogModeHybrid" => Command::LogModeHybrid,
            "JumpToOldestLogs" => Command::JumpToOldestLogs,
            "JumpToNewestLogs" => Command::JumpToNewestLogs,
            "LogScrollUp" => Command::LogScrollUp,
            "LogScrollDown" => Command::LogScrollDown,
            "ToggleHelp" => Command::ToggleHelp,
            "HelpScrollUp" => Command::HelpScrollUp,
            "HelpScrollDown" => Command::HelpScrollDown,
            "ToggleViewMode" => Command::ToggleViewMode,
            "ToggleTaskTree" => Command::ToggleTaskTree,
            "OverlayCancel" => Command::OverlayCancel,
            "OverlayConfirm" => Command::OverlayConfirm,
            "RefreshConfig" => Command::RefreshConfig,
            "RerunTestGroup" => Command::RerunTestGroup,
            "NarrowTestGroup" => Command::NarrowTestGroup,
            "NextFailInTestGroup" => Command::NextFailInTestGroup,
            "PrevFailInTestGroup" => Command::PrevFailInTestGroup,
            "CallFunction1" => Command::CallFunction("fn1".into()),
            "CallFunction2" => Command::CallFunction("fn2".into()),
            _ => return Err(format!("Unknown command: `{s}`")),
        })
    }
}

/// What an InputEvent maps to in the binding table.
#[derive(Debug, Clone)]
pub enum BindingEntry {
    /// Direct command execution
    Command(Command),
    /// Chain group index - user must press another key
    Chain(u32),
}

/// A group of chain continuations.
#[derive(Debug, Clone, Default)]
pub struct ChainGroup {
    /// Optional label shown in status bar (e.g., "Leader", "Test")
    pub label: Option<Box<str>>,
    /// Next keys in the chain (small, O(n) lookup is fine)
    pub bindings: Vec<(InputEvent, BindingEntry)>,
}

impl ChainGroup {
    /// Look up the next key in this chain group.
    pub fn lookup(&self, input: InputEvent) -> Option<&BindingEntry> {
        self.bindings.iter().find(|(k, _)| *k == input).map(|(_, v)| v)
    }
}

/// Keybinding modes corresponding to different UI states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Global,
    Input,
    Pager,
    TaskTree,
    SelectSearch,
    LogSearch,
    TaskLauncher,
    TestFilterLauncher,
}

impl Mode {
    pub const ALL: [Mode; 8] = [
        Mode::Global,
        Mode::Input,
        Mode::Pager,
        Mode::TaskTree,
        Mode::SelectSearch,
        Mode::LogSearch,
        Mode::TaskLauncher,
        Mode::TestFilterLauncher,
    ];

    pub fn config_name(self) -> &'static str {
        match self {
            Mode::Global => "global",
            Mode::Input => "input",
            Mode::Pager => "pager",
            Mode::TaskTree => "task_tree",
            Mode::SelectSearch => "select_search",
            Mode::LogSearch => "log_search",
            Mode::TaskLauncher => "task_launcher",
            Mode::TestFilterLauncher => "test_filter_launcher",
        }
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "global" => Mode::Global,
            "input" => Mode::Input,
            "pager" => Mode::Pager,
            "task_tree" | "tasktree" | "joblist" => Mode::TaskTree,
            "select_search" | "selectsearch" => Mode::SelectSearch,
            "log_search" | "logsearch" => Mode::LogSearch,
            "task_launcher" | "tasklauncher" => Mode::TaskLauncher,
            "test_filter_launcher" | "testfilterlauncher" => Mode::TestFilterLauncher,
            _ => return Err(format!("Unknown mode: `{s}`")),
        })
    }
}

type BindingTable = HashTable<(InputEvent, BindingEntry)>;

/// Keybinding configuration with separate tables per mode.
pub struct Keybinds {
    hasher: RandomState,
    global: BindingTable,
    input: BindingTable,
    pager: BindingTable,
    task_tree: BindingTable,
    select_search: BindingTable,
    log_search: BindingTable,
    task_launcher: BindingTable,
    test_filter_launcher: BindingTable,
    chains: Vec<ChainGroup>,
}

impl Keybinds {
    fn table_lookup<'a>(&self, table: &'a BindingTable, input: InputEvent) -> Option<&'a BindingEntry> {
        let hash = hash_input(&self.hasher, input);
        table.find(hash, |(k, _)| *k == input).map(|(_, entry)| entry)
    }
}

impl Default for Keybinds {
    fn default() -> Self {
        let mut keybinds = Keybinds::new();
        keybinds.load_defaults();
        keybinds
    }
}

impl Keybinds {
    /// Creates an empty keybinds configuration.
    pub fn new() -> Self {
        Keybinds {
            hasher: RandomState::default(),
            global: HashTable::new(),
            input: HashTable::new(),
            pager: HashTable::new(),
            task_tree: HashTable::new(),
            select_search: HashTable::new(),
            log_search: HashTable::new(),
            task_launcher: HashTable::new(),
            test_filter_launcher: HashTable::new(),
            chains: Vec::new(),
        }
    }

    /// Gets a chain group by index.
    pub fn chain(&self, index: u32) -> Option<&ChainGroup> {
        self.chains.get(index as usize)
    }

    /// Gets a mutable chain group by index.
    pub fn chain_mut(&mut self, index: u32) -> Option<&mut ChainGroup> {
        self.chains.get_mut(index as usize)
    }

    /// Adds a chain group and returns its index.
    pub fn add_chain(&mut self, group: ChainGroup) -> u32 {
        let index = self.chains.len() as u32;
        self.chains.push(group);
        index
    }

    fn table_for_mode(&self, mode: Mode) -> &BindingTable {
        match mode {
            Mode::Global => &self.global,
            Mode::Input => &self.input,
            Mode::Pager => &self.pager,
            Mode::TaskTree => &self.task_tree,
            Mode::SelectSearch => &self.select_search,
            Mode::LogSearch => &self.log_search,
            Mode::TaskLauncher => &self.task_launcher,
            Mode::TestFilterLauncher => &self.test_filter_launcher,
        }
    }

    fn load_defaults(&mut self) {
        self.bind(Mode::Global, "C-c", Command::Quit);
        self.bind(Mode::Global, "?", Command::ToggleHelp);

        self.bind(Mode::Input, "C-k", Command::SelectPrev);
        self.bind(Mode::Input, "UP", Command::SelectPrev);
        self.bind(Mode::Input, "C-j", Command::SelectNext);
        self.bind(Mode::Input, "DOWN", Command::SelectNext);
        self.bind(Mode::Input, "C-g", Command::OverlayCancel);
        self.bind(Mode::Input, "ESC", Command::OverlayCancel);
        self.bind(Mode::Input, "C-l", Command::OverlayConfirm);
        self.bind(Mode::Input, "ENTER", Command::OverlayConfirm);

        self.bind(Mode::Pager, "/", Command::SearchLogs);
        self.bind(Mode::Pager, "HOME", Command::JumpToOldestLogs);
        self.bind(Mode::Pager, "END", Command::JumpToNewestLogs);
        self.bind(Mode::Pager, "C-k", Command::LogScrollUp);
        self.bind(Mode::Pager, "C-j", Command::LogScrollDown);
        self.bind(Mode::Pager, "PGUP", Command::HelpScrollUp);
        self.bind(Mode::Pager, "PGDN", Command::HelpScrollDown);
        self.bind(Mode::Pager, "1", Command::LogModeAll);
        self.bind(Mode::Pager, "2", Command::LogModeSelected);
        self.bind(Mode::Pager, "3", Command::LogModeHybrid);

        self.bind(Mode::TaskTree, "j", Command::SelectNext);
        self.bind(Mode::TaskTree, "k", Command::SelectPrev);
        self.bind(Mode::TaskTree, "UP", Command::SelectPrev);
        self.bind(Mode::TaskTree, "DOWN", Command::SelectNext);
        self.bind(Mode::TaskTree, "h", Command::FocusPrimary);
        self.bind(Mode::TaskTree, "l", Command::FocusSecondary);
        self.bind(Mode::TaskTree, "LEFT", Command::FocusPrimary);
        self.bind(Mode::TaskTree, "RIGHT", Command::FocusSecondary);
        self.bind(Mode::TaskTree, "r", Command::RestartTask);
        self.bind(Mode::TaskTree, "d", Command::TerminateTask);
        self.bind(Mode::TaskTree, "s", Command::LaunchTask);
        self.bind(Mode::TaskTree, "g", Command::StartGroup);
        self.bind(Mode::TaskTree, "ENTER", Command::StartSelection);
        self.bind(Mode::TaskTree, "v", Command::ToggleViewMode);
        self.bind(Mode::TaskTree, "\\", Command::ToggleTaskTree);
        self.bind(Mode::TaskTree, "R", Command::RefreshConfig);
        self.bind(Mode::TaskTree, "t", Command::LaunchTestFilter);
        self.bind(Mode::TaskTree, "T", Command::RerunTestGroup);
        self.bind(Mode::TaskTree, "N", Command::NarrowTestGroup);
        self.bind(Mode::TaskTree, "n", Command::NextFailInTestGroup);
        self.bind(Mode::TaskTree, "p", Command::PrevFailInTestGroup);
    }

    /// Binds a key to a command in a specific mode.
    fn bind(&mut self, mode: Mode, key: &str, command: Command) {
        let input: InputEvent = key.parse().expect("invalid default keybinding");
        let hasher = &self.hasher;
        let hash = hash_input(hasher, input);
        let table = match mode {
            Mode::Global => &mut self.global,
            Mode::Input => &mut self.input,
            Mode::Pager => &mut self.pager,
            Mode::TaskTree => &mut self.task_tree,
            Mode::SelectSearch => &mut self.select_search,
            Mode::LogSearch => &mut self.log_search,
            Mode::TaskLauncher => &mut self.task_launcher,
            Mode::TestFilterLauncher => &mut self.test_filter_launcher,
        };
        let entry = BindingEntry::Command(command);
        match table.find_mut(hash, |(k, _)| *k == input) {
            Some(e) => e.1 = entry,
            None => {
                table.insert_unique(hash, (input, entry), |(k, _)| hash_input(hasher, *k));
            }
        }
    }

    /// Sets a binding from parsed config (simple command).
    pub fn set_binding(&mut self, mode: Mode, input: InputEvent, command: Option<Command>) {
        match command {
            Some(cmd) => self.set_binding_entry(mode, input, BindingEntry::Command(cmd)),
            None => self.remove_binding(mode, input),
        }
    }

    /// Sets a binding entry (command or chain) from parsed config.
    pub fn set_binding_entry(&mut self, mode: Mode, input: InputEvent, entry: BindingEntry) {
        let hash = hash_input(&self.hasher, input);
        let hasher = self.hasher.clone();
        let table = self.table_for_mode_mut(mode);
        match table.find_mut(hash, |(k, _)| *k == input) {
            Some(e) => e.1 = entry,
            None => {
                table.insert_unique(hash, (input, entry), |(k, _)| hash_input(&hasher, *k));
            }
        }
    }

    /// Removes a binding from the specified mode.
    pub fn remove_binding(&mut self, mode: Mode, input: InputEvent) {
        let hash = hash_input(&self.hasher, input);
        let table = self.table_for_mode_mut(mode);
        if let Ok(entry) = table.find_entry(hash, |(k, _)| *k == input) {
            entry.remove();
        }
    }

    fn table_for_mode_mut(&mut self, mode: Mode) -> &mut BindingTable {
        match mode {
            Mode::Global => &mut self.global,
            Mode::Input => &mut self.input,
            Mode::Pager => &mut self.pager,
            Mode::TaskTree => &mut self.task_tree,
            Mode::SelectSearch => &mut self.select_search,
            Mode::LogSearch => &mut self.log_search,
            Mode::TaskLauncher => &mut self.task_launcher,
            Mode::TestFilterLauncher => &mut self.test_filter_launcher,
        }
    }

    /// Looks up a binding entry for the given input in the specified mode.
    /// Falls back to global bindings if no mode-specific binding exists.
    pub fn lookup_entry(&self, mode: Mode, input: InputEvent) -> Option<&BindingEntry> {
        if mode != Mode::Global
            && let Some(entry) = self.table_lookup(self.table_for_mode(mode), input)
        {
            return Some(entry);
        }
        self.table_lookup(&self.global, input)
    }

    /// Looks up a command for the given input (returns None for chain entries).
    /// Falls back to global bindings if no mode-specific binding exists.
    pub fn lookup(&self, mode: Mode, input: InputEvent) -> Option<Command> {
        match self.lookup_entry(mode, input) {
            Some(BindingEntry::Command(cmd)) => Some(cmd.clone()),
            _ => None,
        }
    }

    /// Looks up a command only in the specified mode (no fallback).
    #[expect(unused, reason = "kept for user config querying specific mode bindings")]
    pub fn lookup_mode_only(&self, mode: Mode, input: InputEvent) -> Option<Command> {
        match self.table_lookup(self.table_for_mode(mode), input) {
            Some(BindingEntry::Command(cmd)) => Some(cmd.clone()),
            _ => None,
        }
    }

    /// Looks up a binding entry by searching through a chain of modes in order.
    /// Returns the first matching entry found.
    pub fn lookup_entry_chain(&self, modes: &[Mode], input: InputEvent) -> Option<&BindingEntry> {
        let hash = hash_input(&self.hasher, input);
        for &mode in modes {
            let table = self.table_for_mode(mode);
            if let Some((_, entry)) = table.find(hash, |(k, _)| *k == input) {
                return Some(entry);
            }
        }
        None
    }

    /// Looks up a command by searching through a chain of modes in order.
    /// Returns the first matching command found (returns None for chain entries).
    pub fn lookup_chain(&self, modes: &[Mode], input: InputEvent) -> Option<Command> {
        match self.lookup_entry_chain(modes, input) {
            Some(BindingEntry::Command(cmd)) => Some(cmd.clone()),
            _ => None,
        }
    }

    /// Returns an iterator over all bindings in the global mode.
    pub fn global_bindings(&self) -> impl Iterator<Item = (InputEvent, &BindingEntry)> + '_ {
        self.global.iter().map(|(k, v)| (*k, v))
    }

    /// Returns an iterator over all bindings in a specific mode.
    pub fn mode_bindings(&self, mode: Mode) -> impl Iterator<Item = (InputEvent, &BindingEntry)> + '_ {
        self.table_for_mode(mode).iter().map(|(k, v)| (*k, v))
    }

    /// Finds the first key bound to a command across all modes.
    /// When multiple keys are bound to the same command, returns the smallest by Ord for consistency.
    pub fn key_for_command(&self, command: &Command) -> Option<InputEvent> {
        self.global
            .iter()
            .chain(self.task_tree.iter())
            .chain(self.pager.iter())
            .chain(self.input.iter())
            .chain(self.select_search.iter())
            .chain(self.log_search.iter())
            .chain(self.task_launcher.iter())
            .filter_map(|(key, entry)| match entry {
                BindingEntry::Command(cmd) if cmd == command => Some(*key),
                _ => None,
            })
            .min()
    }
}

impl Command {
    /// Returns a short display name for the command.
    pub fn display_name(&self) -> &'static str {
        match self {
            Command::Quit => "Quit",
            Command::SelectNext => "Next",
            Command::SelectPrev => "Prev",
            Command::FocusPrimary => "Focus Left",
            Command::FocusSecondary => "Focus Right",
            Command::RestartTask => "Restart",
            Command::TerminateTask => "Terminate",
            Command::LaunchTask => "Launch",
            Command::LaunchTestFilter => "Test Filter",
            Command::StartGroup => "Start Group",
            Command::StartSelection => "Profile",
            Command::SearchLogs => "Search",
            Command::LogModeAll => "Log: All",
            Command::LogModeSelected => "Log: Selected",
            Command::LogModeHybrid => "Log: Hybrid",
            Command::JumpToOldestLogs => "Oldest Logs",
            Command::JumpToNewestLogs => "Newest Logs",
            Command::LogScrollUp => "Scroll Up",
            Command::LogScrollDown => "Scroll Down",
            Command::ToggleHelp => "Help",
            Command::HelpScrollUp => "Help Up",
            Command::HelpScrollDown => "Help Down",
            Command::ToggleViewMode => "Toggle View",
            Command::ToggleTaskTree => "Toggle Tasks",
            Command::OverlayCancel => "Cancel",
            Command::OverlayConfirm => "Confirm",
            Command::RefreshConfig => "Refresh Config",
            Command::RerunTestGroup => "Rerun Tests",
            Command::NarrowTestGroup => "Narrow Tests",
            Command::NextFailInTestGroup => "Next Fail",
            Command::PrevFailInTestGroup => "Prev Fail",
            Command::CallFunction(name) if &**name == "fn1" => "Call fn1",
            Command::CallFunction(name) if &**name == "fn2" => "Call fn2",
            Command::CallFunction(_) => "Call Function",
            Command::SetFunction { name, .. } if &**name == "fn1" => "Set fn1",
            Command::SetFunction { name, .. } if &**name == "fn2" => "Set fn2",
            Command::SetFunction { .. } => "Set Function",
        }
    }

    /// Returns the config name for the command (used in TOML config files).
    pub fn config_name(&self) -> &'static str {
        match self {
            Command::Quit => "Quit",
            Command::SelectNext => "SelectNext",
            Command::SelectPrev => "SelectPrev",
            Command::FocusPrimary => "FocusPrimary",
            Command::FocusSecondary => "FocusSecondary",
            Command::RestartTask => "RestartTask",
            Command::TerminateTask => "TerminateTask",
            Command::LaunchTask => "LaunchTask",
            Command::LaunchTestFilter => "LaunchTestFilter",
            Command::StartGroup => "StartGroup",
            Command::StartSelection => "SelectProfile",
            Command::SearchLogs => "SearchLogs",
            Command::LogModeAll => "LogModeAll",
            Command::LogModeSelected => "LogModeSelected",
            Command::LogModeHybrid => "LogModeHybrid",
            Command::JumpToOldestLogs => "JumpToOldestLogs",
            Command::JumpToNewestLogs => "JumpToNewestLogs",
            Command::LogScrollUp => "LogScrollUp",
            Command::LogScrollDown => "LogScrollDown",
            Command::ToggleHelp => "ToggleHelp",
            Command::HelpScrollUp => "HelpScrollUp",
            Command::HelpScrollDown => "HelpScrollDown",
            Command::ToggleViewMode => "ToggleViewMode",
            Command::ToggleTaskTree => "ToggleTaskTree",
            Command::OverlayCancel => "OverlayCancel",
            Command::OverlayConfirm => "OverlayConfirm",
            Command::RefreshConfig => "RefreshConfig",
            Command::RerunTestGroup => "RerunTestGroup",
            Command::NarrowTestGroup => "NarrowTestGroup",
            Command::NextFailInTestGroup => "NextFailInTestGroup",
            Command::PrevFailInTestGroup => "PrevFailInTestGroup",
            Command::CallFunction(name) if &**name == "fn1" => "CallFunction1",
            Command::CallFunction(name) if &**name == "fn2" => "CallFunction2",
            Command::CallFunction(_) => "CallFunction",
            Command::SetFunction { .. } => "SetFunction",
        }
    }
}

#[inline]
fn hash_input(hasher: &RandomState, input: InputEvent) -> u64 {
    let mut h = hasher.build_hasher();
    h.write_u64(input.0);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_event_parsing() {
        let key: InputEvent = "j".parse().unwrap();
        assert_eq!(key.as_char(), Some('j'));

        let key: InputEvent = "C-c".parse().unwrap();
        assert_eq!(key.as_char(), Some('c'));
        assert!(key.modifiers().contains(KeyModifiers::CONTROL));

        let key: InputEvent = "ESC".parse().unwrap();
        assert!(key.named_key().is_some());
        assert_eq!(key.to_string(), "ESC");

        let key: InputEvent = "C-ENTER".parse().unwrap();
        assert!(key.modifiers().contains(KeyModifiers::CONTROL));
        assert!(key.named_key().is_some());
    }

    #[test]
    fn space_key_parsing() {
        let key: InputEvent = "SPACE".parse().unwrap();
        assert_eq!(key.as_char(), Some(' '));
        assert_eq!(key.to_string(), "SPACE");

        let key: InputEvent = "C-SPACE".parse().unwrap();
        assert_eq!(key.as_char(), Some(' '));
        assert!(key.modifiers().contains(KeyModifiers::CONTROL));
        assert_eq!(key.to_string(), "C-SPACE");

        let err = " ".parse::<InputEvent>().unwrap_err();
        assert!(err.contains("SPACE"), "error should mention SPACE: {}", err);
    }

    #[test]
    fn default_keybinds_and_fallback() {
        let keybinds = Keybinds::default();

        let j: InputEvent = "j".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::TaskTree, j), Some(Command::SelectNext));
        assert_eq!(keybinds.lookup(Mode::Global, j), None);

        let ctrl_c: InputEvent = "C-c".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::SelectSearch, ctrl_c), Some(Command::Quit));
        assert_eq!(keybinds.lookup(Mode::Global, ctrl_c), Some(Command::Quit));

        let home: InputEvent = "HOME".parse().unwrap();
        let end: InputEvent = "END".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::Pager, home), Some(Command::JumpToOldestLogs));
        assert_eq!(keybinds.lookup(Mode::Pager, end), Some(Command::JumpToNewestLogs));
    }

    #[test]
    fn lookup_chain_traverses_modes() {
        let keybinds = Keybinds::default();

        let j: InputEvent = "j".parse().unwrap();
        assert_eq!(keybinds.lookup_chain(&[Mode::TaskTree, Mode::Pager, Mode::Global], j), Some(Command::SelectNext));

        let ctrl_c: InputEvent = "C-c".parse().unwrap();
        assert_eq!(keybinds.lookup_chain(&[Mode::TaskTree, Mode::Pager, Mode::Global], ctrl_c), Some(Command::Quit));

        let slash: InputEvent = "/".parse().unwrap();
        assert_eq!(
            keybinds.lookup_chain(&[Mode::TaskTree, Mode::Pager, Mode::Global], slash),
            Some(Command::SearchLogs)
        );
    }

    #[test]
    fn input_mode_bindings() {
        let keybinds = Keybinds::default();

        let ctrl_k: InputEvent = "C-k".parse().unwrap();
        let esc: InputEvent = "ESC".parse().unwrap();
        let enter: InputEvent = "ENTER".parse().unwrap();

        assert_eq!(keybinds.lookup(Mode::Input, ctrl_k), Some(Command::SelectPrev));
        assert_eq!(keybinds.lookup(Mode::Input, esc), Some(Command::OverlayCancel));
        assert_eq!(keybinds.lookup(Mode::Input, enter), Some(Command::OverlayConfirm));

        assert_eq!(
            keybinds.lookup_chain(&[Mode::SelectSearch, Mode::Input, Mode::Global], ctrl_k),
            Some(Command::SelectPrev)
        );
    }
}
