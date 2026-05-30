//! Crossterm front-end driving a [`PhraseInput`] with in-place rendering.

use std::fmt::Write as _;
use std::io::{self, Write};

use bip39::{Language, Mnemonic};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    queue,
    style::Print,
    terminal::{self, Clear, ClearType},
};

use crate::PhraseInput;

// Minimal SGR escapes. They carry no newlines, so they don't affect the
// line-count bookkeeping used for in-place redraws.
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Result of an interactive [`read_mnemonic`] session.
pub enum Outcome {
    /// A complete, checksum-valid mnemonic was entered.
    Valid(Mnemonic),
    /// All words were entered, but the checksum is invalid.
    InvalidChecksum,
    /// The user cancelled (Esc or Ctrl-C).
    Aborted,
}

/// Interactively read a `word_count`-word mnemonic in `lang` from the terminal.
///
/// Drives a [`PhraseInput`] in crossterm raw mode, rendering candidate words in
/// place as the user types:
///
/// - digits `1`–`9` and `0` pick a numbered shortcut when ten or fewer words match;
/// - Tab / Enter / Space accept a unique match;
/// - Backspace edits, stepping back to the previous word when the buffer is empty;
/// - Esc (or Ctrl-C) aborts.
///
/// The candidate area is wiped from the screen before returning, so the entered
/// words are not left on display.
pub fn read_mnemonic(lang: Language, word_count: usize) -> io::Result<Outcome> {
    let mut out = io::stdout();
    terminal::enable_raw_mode()?;
    let result = run(&mut out, lang, word_count);
    // Always restore the terminal, even if `run` errored.
    let _ = terminal::disable_raw_mode();
    let _ = queue!(out, cursor::Show);
    let _ = out.flush();
    result
}

fn run(out: &mut io::Stdout, lang: Language, word_count: usize) -> io::Result<Outcome> {
    let mut input = PhraseInput::new(lang, word_count);
    let mut lines = 0u16;

    loop {
        lines = render(out, &input, lines)?;

        let key = match event::read()? {
            Event::Key(k) if k.kind != KeyEventKind::Release => k,
            _ => continue,
        };

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            clear_block(out, lines)?;
            return Ok(Outcome::Aborted);
        }

        match key.code {
            KeyCode::Esc => {
                clear_block(out, lines)?;
                return Ok(Outcome::Aborted);
            }
            KeyCode::Backspace => {
                input.backspace();
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Char(' ') => {
                if let Some(word) = input.accepted() {
                    input.commit(word);
                }
            }
            // Digits are shortcuts, never letters (no BIP39 word contains one).
            // Keys 1-9 select positions 1-9; key 0 selects the tenth.
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let n = if c == '0' {
                    10
                } else {
                    (c as u8 - b'0') as usize
                };
                if let Some(word) = input.shortcut(n) {
                    input.commit(word);
                }
            }
            KeyCode::Char(c) => {
                input.push_char(c);
            }
            _ => {}
        }

        if input.is_complete() {
            clear_block(out, lines)?;
            return Ok(match input.validate() {
                Ok(mnemonic) => Outcome::Valid(mnemonic),
                Err(_) => Outcome::InvalidChecksum,
            });
        }
    }
}

/// Redraw the dynamic block in place and return the number of lines it spans.
fn render(out: &mut io::Stdout, input: &PhraseInput, prev_lines: u16) -> io::Result<u16> {
    move_to_block_top(out, prev_lines)?;

    let content = frame(input);
    let lines = content.matches('\n').count() as u16;
    queue!(out, Print(content))?;
    out.flush()?;
    Ok(lines)
}

/// Move the cursor to the top of the previously drawn block and clear downward,
/// leaving the cursor there for whatever is printed next.
fn clear_block(out: &mut io::Stdout, prev_lines: u16) -> io::Result<()> {
    move_to_block_top(out, prev_lines)?;
    out.flush()
}

fn move_to_block_top(out: &mut io::Stdout, prev_lines: u16) -> io::Result<()> {
    queue!(out, cursor::MoveToColumn(0))?;
    if prev_lines > 0 {
        queue!(out, cursor::MoveUp(prev_lines))?;
    }
    queue!(out, Clear(ClearType::FromCursorDown))?;
    Ok(())
}

/// Build the dynamic block. The final (input) line carries no trailing newline,
/// so the cursor ends right after the buffer and the newline count equals the
/// number of rows to move back up on the next redraw.
fn frame(input: &PhraseInput) -> String {
    let mut s = String::new();
    let position = input.current_index() + 1;
    let total = input.target_len();

    let _ = write!(s, "{DIM}  Word {position}/{total}{RESET}\r\n");

    let candidates = input.candidates();
    if input.buffer().is_empty() {
        let _ = write!(s, "{DIM}  type to search…{RESET}\r\n");
    } else if candidates.is_empty() {
        let _ = write!(s, "{RED}  (no match){RESET}\r\n");
    } else if let Some(shortcuts) = input.shortcuts() {
        for (i, word) in shortcuts.iter().enumerate() {
            // Positions 1-9 use their digit; the tenth uses the "0" key.
            let key = if i == 9 { 0 } else { i + 1 };
            let _ = write!(s, "  {CYAN}{key}){RESET} {word}\r\n");
        }
    } else {
        let _ = write!(
            s,
            "{DIM}  {} words match — keep typing{RESET}\r\n",
            candidates.len()
        );
    }

    let _ = write!(s, "  {BOLD}>{RESET} {}", input.buffer());
    s
}
