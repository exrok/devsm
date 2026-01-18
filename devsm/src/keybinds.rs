use std::{
    fmt::{self, Display, Write},
    hash::{BuildHasher, Hasher},
    str::FromStr,
};

use foldhash::quality::RandomState;
use hashbrown::HashTable;
use vtui::event::{KeyCode, KeyEvent, KeyModifiers};

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
            f.write_char(ch)
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
        } else if rem.len() == 1 {
            Ok(InputEvent(raw_base | (rem.as_bytes()[0] as u64)))
        } else {
            Err(format!("Unknown key: `{rem}` in binding `{input}`"))
        }
    }
}

/// Commands that can be triggered by keybindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Quit,
    SelectNext,
    SelectPrev,
    FocusPrimary,
    FocusSecondary,
    RestartTask,
    TerminateTask,
    LaunchTask,
    StartGroup,
    SelectProfile,
    SearchLogs,
    LogModeAll,
    LogModeSelected,
    LogModeHybrid,
    TailTopLog,
    TailBottomLog,
    LogScrollUp,
    LogScrollDown,
    ToggleHelp,
    HelpScrollUp,
    HelpScrollDown,
    ToggleViewMode,
    OverlayCancel,
    OverlayConfirm,
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
            "StartGroup" => Command::StartGroup,
            "SelectProfile" => Command::SelectProfile,
            "SearchLogs" => Command::SearchLogs,
            "LogModeAll" => Command::LogModeAll,
            "LogModeSelected" => Command::LogModeSelected,
            "LogModeHybrid" => Command::LogModeHybrid,
            "TailTopLog" => Command::TailTopLog,
            "TailBottomLog" => Command::TailBottomLog,
            "LogScrollUp" => Command::LogScrollUp,
            "LogScrollDown" => Command::LogScrollDown,
            "ToggleHelp" => Command::ToggleHelp,
            "HelpScrollUp" => Command::HelpScrollUp,
            "HelpScrollDown" => Command::HelpScrollDown,
            "ToggleViewMode" => Command::ToggleViewMode,
            "OverlayCancel" => Command::OverlayCancel,
            "OverlayConfirm" => Command::OverlayConfirm,
            _ => return Err(format!("Unknown command: `{s}`")),
        })
    }
}

/// Keybinding modes corresponding to different UI states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Global,
    JobList,
    SelectSearch,
    LogSearch,
    TaskLauncher,
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "global" => Mode::Global,
            "joblist" => Mode::JobList,
            "select_search" | "selectsearch" => Mode::SelectSearch,
            "log_search" | "logsearch" => Mode::LogSearch,
            "task_launcher" | "tasklauncher" => Mode::TaskLauncher,
            _ => return Err(format!("Unknown mode: `{s}`")),
        })
    }
}

type BindingTable = HashTable<(InputEvent, Command)>;

/// Keybinding configuration with separate tables per mode.
pub struct Keybinds {
    hasher: RandomState,
    global: BindingTable,
    joblist: BindingTable,
    select_search: BindingTable,
    log_search: BindingTable,
    task_launcher: BindingTable,
}

impl Keybinds {
    fn table_lookup(&self, table: &BindingTable, input: InputEvent) -> Option<Command> {
        table.find(hash_input(&self.hasher, input), |(k, _)| *k == input).map(|(_, cmd)| *cmd)
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
            joblist: HashTable::new(),
            select_search: HashTable::new(),
            log_search: HashTable::new(),
            task_launcher: HashTable::new(),
        }
    }

    fn table_for_mode(&self, mode: Mode) -> &BindingTable {
        match mode {
            Mode::Global => &self.global,
            Mode::JobList => &self.joblist,
            Mode::SelectSearch => &self.select_search,
            Mode::LogSearch => &self.log_search,
            Mode::TaskLauncher => &self.task_launcher,
        }
    }

    fn load_defaults(&mut self) {
        self.bind(Mode::Global, "C-c", Command::Quit);
        self.bind(Mode::Global, "/", Command::SearchLogs);
        self.bind(Mode::Global, "g", Command::StartGroup);
        self.bind(Mode::Global, "r", Command::RestartTask);
        self.bind(Mode::Global, "d", Command::TerminateTask);
        self.bind(Mode::Global, " ", Command::LaunchTask);
        self.bind(Mode::Global, "1", Command::LogModeAll);
        self.bind(Mode::Global, "2", Command::LogModeSelected);
        self.bind(Mode::Global, "3", Command::LogModeHybrid);
        self.bind(Mode::Global, "p", Command::SelectProfile);
        self.bind(Mode::Global, "k", Command::SelectPrev);
        self.bind(Mode::Global, "j", Command::SelectNext);
        self.bind(Mode::Global, "h", Command::FocusPrimary);
        self.bind(Mode::Global, "l", Command::FocusSecondary);
        self.bind(Mode::Global, "END", Command::TailTopLog);
        self.bind(Mode::Global, "C-END", Command::TailBottomLog);
        self.bind(Mode::Global, "C-k", Command::LogScrollUp);
        self.bind(Mode::Global, "C-j", Command::LogScrollDown);
        self.bind(Mode::Global, "?", Command::ToggleHelp);
        self.bind(Mode::Global, "PGUP", Command::HelpScrollUp);
        self.bind(Mode::Global, "PGDN", Command::HelpScrollDown);
        self.bind(Mode::Global, "v", Command::ToggleViewMode);

        self.bind(Mode::SelectSearch, "C-k", Command::SelectPrev);
        self.bind(Mode::SelectSearch, "UP", Command::SelectPrev);
        self.bind(Mode::SelectSearch, "C-j", Command::SelectNext);
        self.bind(Mode::SelectSearch, "DOWN", Command::SelectNext);
        self.bind(Mode::SelectSearch, "C-g", Command::OverlayCancel);
        self.bind(Mode::SelectSearch, "ESC", Command::OverlayCancel);
        self.bind(Mode::SelectSearch, "C-l", Command::OverlayConfirm);
        self.bind(Mode::SelectSearch, "ENTER", Command::OverlayConfirm);

        self.bind(Mode::LogSearch, "C-k", Command::SelectPrev);
        self.bind(Mode::LogSearch, "UP", Command::SelectPrev);
        self.bind(Mode::LogSearch, "C-j", Command::SelectNext);
        self.bind(Mode::LogSearch, "DOWN", Command::SelectNext);
        self.bind(Mode::LogSearch, "C-g", Command::OverlayCancel);
        self.bind(Mode::LogSearch, "ESC", Command::OverlayCancel);
        self.bind(Mode::LogSearch, "ENTER", Command::OverlayConfirm);

        self.bind(Mode::TaskLauncher, "C-k", Command::SelectPrev);
        self.bind(Mode::TaskLauncher, "UP", Command::SelectPrev);
        self.bind(Mode::TaskLauncher, "C-j", Command::SelectNext);
        self.bind(Mode::TaskLauncher, "DOWN", Command::SelectNext);
        self.bind(Mode::TaskLauncher, "C-g", Command::OverlayCancel);
        self.bind(Mode::TaskLauncher, "ESC", Command::OverlayCancel);
        self.bind(Mode::TaskLauncher, "ENTER", Command::OverlayConfirm);
    }

    /// Binds a key to a command in a specific mode.
    fn bind(&mut self, mode: Mode, key: &str, command: Command) {
        let input: InputEvent = key.parse().expect("invalid default keybinding");
        let hasher = &self.hasher;
        let hash = hash_input(hasher, input);
        let table = match mode {
            Mode::Global => &mut self.global,
            Mode::JobList => &mut self.joblist,
            Mode::SelectSearch => &mut self.select_search,
            Mode::LogSearch => &mut self.log_search,
            Mode::TaskLauncher => &mut self.task_launcher,
        };
        match table.find_mut(hash, |(k, _)| *k == input) {
            Some(entry) => entry.1 = command,
            None => {
                table.insert_unique(hash, (input, command), |(k, _)| hash_input(hasher, *k));
            }
        }
    }

    /// Sets a binding from parsed config.
    pub fn set_binding(&mut self, mode: Mode, input: InputEvent, command: Option<Command>) {
        let hasher = &self.hasher;
        let hash = hash_input(hasher, input);
        let table = match mode {
            Mode::Global => &mut self.global,
            Mode::JobList => &mut self.joblist,
            Mode::SelectSearch => &mut self.select_search,
            Mode::LogSearch => &mut self.log_search,
            Mode::TaskLauncher => &mut self.task_launcher,
        };
        match command {
            Some(cmd) => match table.find_mut(hash, |(k, _)| *k == input) {
                Some(entry) => entry.1 = cmd,
                None => {
                    table.insert_unique(hash, (input, cmd), |(k, _)| hash_input(hasher, *k));
                }
            },
            None => {
                if let Ok(entry) = table.find_entry(hash, |(k, _)| *k == input) {
                    entry.remove();
                }
            }
        }
    }

    /// Looks up a command for the given input in the specified mode.
    /// Falls back to global bindings if no mode-specific binding exists.
    pub fn lookup(&self, mode: Mode, input: InputEvent) -> Option<Command> {
        if mode != Mode::Global
            && let Some(cmd) = self.table_lookup(self.table_for_mode(mode), input) {
                return Some(cmd);
            }
        self.table_lookup(&self.global, input)
    }

    /// Looks up a command only in the specified mode (no fallback).
    pub fn lookup_mode_only(&self, mode: Mode, input: InputEvent) -> Option<Command> {
        self.table_lookup(self.table_for_mode(mode), input)
    }

    /// Returns an iterator over all bindings in the global mode.
    pub fn global_bindings(&self) -> impl Iterator<Item = (InputEvent, Command)> + '_ {
        self.global.iter().map(|(k, v)| (*k, *v))
    }

    /// Returns an iterator over all bindings in a specific mode.
    pub fn mode_bindings(&self, mode: Mode) -> impl Iterator<Item = (InputEvent, Command)> + '_ {
        self.table_for_mode(mode).iter().map(|(k, v)| (*k, *v))
    }
}

impl Command {
    /// Returns a short display name for the command.
    pub fn display_name(self) -> &'static str {
        match self {
            Command::Quit => "Quit",
            Command::SelectNext => "Next",
            Command::SelectPrev => "Prev",
            Command::FocusPrimary => "Focus Left",
            Command::FocusSecondary => "Focus Right",
            Command::RestartTask => "Restart",
            Command::TerminateTask => "Terminate",
            Command::LaunchTask => "Launch",
            Command::StartGroup => "Start Group",
            Command::SelectProfile => "Profile",
            Command::SearchLogs => "Search",
            Command::LogModeAll => "Log: All",
            Command::LogModeSelected => "Log: Selected",
            Command::LogModeHybrid => "Log: Hybrid",
            Command::TailTopLog => "Tail Top",
            Command::TailBottomLog => "Tail Bottom",
            Command::LogScrollUp => "Scroll Up",
            Command::LogScrollDown => "Scroll Down",
            Command::ToggleHelp => "Help",
            Command::HelpScrollUp => "Help Up",
            Command::HelpScrollDown => "Help Down",
            Command::ToggleViewMode => "Toggle View",
            Command::OverlayCancel => "Cancel",
            Command::OverlayConfirm => "Confirm",
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
    fn default_keybinds_and_fallback() {
        let keybinds = Keybinds::default();

        let j: InputEvent = "j".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::Global, j), Some(Command::SelectNext));

        let ctrl_c: InputEvent = "C-c".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::SelectSearch, ctrl_c), Some(Command::Quit));

        let end: InputEvent = "END".parse().unwrap();
        let ctrl_end: InputEvent = "C-END".parse().unwrap();
        assert_eq!(keybinds.lookup(Mode::Global, end), Some(Command::TailTopLog));
        assert_eq!(keybinds.lookup(Mode::Global, ctrl_end), Some(Command::TailBottomLog));
    }
}
