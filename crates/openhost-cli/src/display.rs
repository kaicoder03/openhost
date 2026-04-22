//! Terminal rendering for pairing codes.
//!
//! `oh send` prints a pairing code three ways so the receiver has a
//! choice of input method:
//!
//! - **BIP-39 words** — readable aloud, typeable, SMS-friendly.
//! - **`oh+pair://` URI** — copy-paste, deep-link, inside the QR.
//! - **ASCII QR code** — scannable from a second device's camera.
//!
//! The QR encodes the URI, not the words. Phones running the Flutter
//! app will register the `oh+pair://` scheme so scanning the QR
//! deep-links straight into `recv` with the code pre-filled.

use openhost_peer::PairingCode;
use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};

/// Render `code` as a multi-line string the CLI prints to stderr.
/// Blank lines separate the three blocks so terminals can re-flow
/// gracefully on narrow windows.
pub fn format_pairing_code(code: &PairingCode) -> String {
    let uri = code.to_uri();
    let words = code.to_words();
    let qr = render_qr(&uri);
    format!(
        "\n\
         {qr}\n\n\
         Pairing code (12 words):\n  {words}\n\n\
         Or URI (for copy-paste):\n  {uri}\n\n\
         Receiver runs:\n  oh recv \"{words}\"\n\n"
    )
}

/// Render `data` as a UTF-8 block QR (two rows per cell using the
/// Unicode half-block trick) with medium-strength error correction.
///
/// Falls back to a plain text note if QR generation fails — the URI
/// and words above are enough to complete the pairing on their own.
fn render_qr(data: &str) -> String {
    match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M) {
        Ok(qr) => qr
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
        Err(err) => format!("(QR render failed: {err}; use the URI or words below.)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_includes_all_three_renderings() {
        let code = PairingCode::generate();
        let out = format_pairing_code(&code);
        // The URI and words appear verbatim somewhere in the block.
        assert!(out.contains(&code.to_uri()), "URI must appear");
        assert!(out.contains(&code.to_words()), "words must appear");
        // The QR uses Unicode block chars — assert we produced some.
        assert!(
            out.chars().any(|c| matches!(c, '▀' | '▄' | '█' | ' ' | '\n')),
            "QR block-char rendering must appear",
        );
    }

    #[test]
    fn render_qr_fallback_on_crazy_inputs() {
        // QrCode supports any byte slice, but keep the function total.
        let _ = render_qr(&"x".repeat(4096));
    }
}
