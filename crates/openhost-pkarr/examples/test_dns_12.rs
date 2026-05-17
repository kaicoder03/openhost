use pkarr::dns::Name;

fn main() {
    let base = "_answer-something";
    let name_str = "_answer-something-0.other.zone.";
    let name = Name::new_unchecked(name_str);

    let first_label = name.iter().next().unwrap();
    let label_bytes = first_label.as_ref();

    if label_bytes.starts_with(b"_") {
        let label_str = std::str::from_utf8(label_bytes).unwrap();
        let lower = label_str.to_lowercase();
        if lower.starts_with(base) {
            println!("Match!");
            let idx_str = &lower[base.len()..];
            println!("Remaining: '{}'", idx_str);
            if let Some(i) = idx_str.strip_prefix('-') {
                 println!("Idx: '{}'", i);
            }
        }
    }
}
