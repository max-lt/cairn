//! Reusable interactive BIP39 mnemonic entry for terminal programs.
//!
//! The crate is split in two layers so it can be reused beyond this CLI:
//!
//! - [`PhraseInput`]: a pure, I/O-free state machine for entering a mnemonic
//!   word by word. It exposes the candidate words for the current prefix and
//!   the "numbered shortcuts" rule (active only when fewer than ten words
//!   match). Fully testable without a terminal, and usable with any renderer.
//! - [`read_mnemonic`] (feature `crossterm`, enabled by default): a ready-made
//!   crossterm front-end that drives a [`PhraseInput`] and renders candidates
//!   in place as the user types.
//!
//! All secret material held by [`PhraseInput`] is zeroized on drop, and the
//! returned [`Mnemonic`] zeroizes itself on drop as well.

pub use bip39::{self, Language, Mnemonic};
use zeroize::Zeroize;

#[cfg(feature = "crossterm")]
mod tui;
#[cfg(feature = "crossterm")]
pub use tui::{Outcome, read_mnemonic};

/// Valid BIP39 mnemonic lengths, in words.
pub const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// State machine for entering a BIP39 mnemonic one word at a time.
///
/// Holds the committed words plus the in-progress buffer for the current word.
/// Drive it by feeding key actions ([`push_char`](Self::push_char),
/// [`backspace`](Self::backspace), [`commit`](Self::commit)) and reading back
/// the [`candidates`](Self::candidates) / [`shortcuts`](Self::shortcuts) to
/// render. All secret material is zeroized on drop.
pub struct PhraseInput {
    lang: Language,
    target_len: usize,
    words: Vec<String>,
    buffer: String,
}

impl Drop for PhraseInput {
    fn drop(&mut self) {
        self.words.zeroize();
        self.buffer.zeroize();
    }
}

impl PhraseInput {
    /// Create an input for a mnemonic of `target_len` words in `lang`.
    ///
    /// `target_len` is normally one of [`VALID_WORD_COUNTS`]; other values are
    /// accepted but can never produce a checksum-valid mnemonic.
    pub fn new(lang: Language, target_len: usize) -> Self {
        Self {
            lang,
            target_len,
            words: Vec::new(),
            buffer: String::new(),
        }
    }

    /// The wordlist language.
    pub fn language(&self) -> Language {
        self.lang
    }

    /// The number of words the mnemonic should contain.
    pub fn target_len(&self) -> usize {
        self.target_len
    }

    /// The committed (fully chosen) words so far.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// The in-progress prefix for the current word.
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// Index of the word currently being entered (0-based).
    pub fn current_index(&self) -> usize {
        self.words.len()
    }

    /// Whether all `target_len` words have been committed.
    pub fn is_complete(&self) -> bool {
        self.words.len() >= self.target_len
    }

    /// Wordlist entries matching the current buffer prefix, in wordlist order.
    /// The words themselves are `'static`; the slice borrows from `self`.
    pub fn candidates(&self) -> &[&'static str] {
        self.lang.words_by_prefix(&self.buffer)
    }

    /// Numbered shortcut candidates: `Some` only when between 1 and 10 words
    /// match — the ten digit keys `1`–`9` and `0` map to positions 1 through
    /// 10. `None` means "too many to shortcut, keep typing" (or, with an
    /// empty/invalid prefix, "no usable shortcuts").
    pub fn shortcuts(&self) -> Option<&[&'static str]> {
        let c = self.candidates();
        (1..=10).contains(&c.len()).then_some(c)
    }

    /// Append a letter to the current buffer. Non-alphabetic input is ignored.
    /// Returns whether the buffer changed.
    pub fn push_char(&mut self, c: char) -> bool {
        if !c.is_ascii_alphabetic() {
            return false;
        }

        self.buffer.push(c.to_ascii_lowercase());
        true
    }

    /// Delete the last buffer character. If the buffer is empty, pull the last
    /// committed word back into the buffer for re-editing. Returns whether
    /// anything changed.
    pub fn backspace(&mut self) -> bool {
        if self.buffer.pop().is_some() {
            return true;
        }

        if let Some(prev) = self.words.pop() {
            self.buffer = prev;
            return true;
        }

        false
    }

    /// The word that "accept" (Tab/Enter/Space) would commit: the sole
    /// candidate when exactly one matches, otherwise `None`.
    pub fn accepted(&self) -> Option<&'static str> {
        match self.candidates() {
            [w] => Some(*w),
            _ => None,
        }
    }

    /// The word for 1-based shortcut position `n` (1..=10), if shortcuts are
    /// active and `n` is in range. The digit key `0` corresponds to `n == 10`.
    pub fn shortcut(&self, n: usize) -> Option<&'static str> {
        let c = self.shortcuts()?;
        c.get(n.checked_sub(1)?).copied()
    }

    /// Commit a word and advance to the next slot. The word should come from
    /// [`accepted`](Self::accepted) or [`shortcut`](Self::shortcut). Does
    /// nothing once [`is_complete`](Self::is_complete).
    pub fn commit(&mut self, word: &str) {
        if self.is_complete() {
            return;
        }

        self.words.push(word.to_string());
        self.buffer.zeroize();
    }

    /// Parse the committed words into a validated [`Mnemonic`], checking word
    /// count and checksum. Only meaningful once [`is_complete`](Self::is_complete).
    pub fn validate(&self) -> Result<Mnemonic, bip39::Error> {
        let mut phrase = self.words.join(" ");
        let result = Mnemonic::parse_in(self.lang, phrase.as_str());
        phrase.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type a prefix and commit its unique completion. Panics if the prefix is
    /// not unique, which keeps the tests honest about the wordlist.
    fn type_word(p: &mut PhraseInput, prefix: &str) {
        for c in prefix.chars() {
            p.push_char(c);
        }

        let word = p.accepted().expect("prefix should be unique");
        p.commit(word);
    }

    #[test]
    fn unique_prefix_resolves_to_one_word() {
        let mut p = PhraseInput::new(Language::English, 12);
        for c in "aba".chars() {
            p.push_char(c);
        }

        assert_eq!(p.candidates(), &["abandon"]);
        assert_eq!(p.accepted(), Some("abandon"));
    }

    #[test]
    fn shortcuts_active_below_ten_matches() {
        let mut p = PhraseInput::new(Language::English, 12);
        for c in "abs".chars() {
            p.push_char(c);
        }

        // absent, absorb, abstract, absurd
        let sc = p.shortcuts().expect("4 matches should enable shortcuts");
        assert_eq!(sc, &["absent", "absorb", "abstract", "absurd"]);
        assert_eq!(p.shortcut(1), Some("absent"));
        assert_eq!(p.shortcut(4), Some("absurd"));
        assert_eq!(p.shortcut(5), None);
    }

    #[test]
    fn shortcuts_active_at_exactly_ten_matches() {
        let mut p = PhraseInput::new(Language::English, 12);
        for c in "ab".chars() {
            p.push_char(c);
        }

        // "ab" matches exactly ten words: digit keys 1-9 and 0 cover them.
        assert_eq!(p.candidates().len(), 10);
        assert!(p.shortcuts().is_some());
        assert_eq!(p.shortcut(10), Some("abuse")); // the "0" key, last of ten
    }

    #[test]
    fn shortcuts_disabled_above_ten_matches() {
        let mut p = PhraseInput::new(Language::English, 12);
        for c in "he".chars() {
            p.push_char(c);
        }

        // "he" matches eleven words — one too many to shortcut.
        assert_eq!(p.candidates().len(), 11);
        assert!(p.shortcuts().is_none());
    }

    #[test]
    fn backspace_on_empty_buffer_reopens_previous_word() {
        let mut p = PhraseInput::new(Language::English, 12);
        type_word(&mut p, "zoo");
        assert_eq!(p.current_index(), 1);
        assert!(p.buffer().is_empty());

        assert!(p.backspace());
        assert_eq!(p.current_index(), 0);
        assert_eq!(p.buffer(), "zoo");
    }

    #[test]
    fn complete_phrase_with_valid_checksum_parses() {
        let mut p = PhraseInput::new(Language::English, 12);
        for _ in 0..11 {
            type_word(&mut p, "abandon");
        }
        type_word(&mut p, "about");

        assert!(p.is_complete());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn complete_phrase_with_bad_checksum_is_rejected() {
        let mut p = PhraseInput::new(Language::English, 12);
        for _ in 0..12 {
            type_word(&mut p, "abandon");
        }

        assert!(p.is_complete());
        assert!(matches!(p.validate(), Err(bip39::Error::InvalidChecksum)));
    }
}
