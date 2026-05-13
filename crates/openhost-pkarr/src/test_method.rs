
use pkarr::simple_dns::Name;
fn check(name: &Name) {
    if let Some(label) = name.iter().next() {
        // label is simple_dns::Label
        let _ = label.len();
    }
}
