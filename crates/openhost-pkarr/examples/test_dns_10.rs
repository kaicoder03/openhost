use pkarr::dns::Name;

fn main() {
    let name_str = "_answer.something.0";
    let name = Name::new_unchecked(name_str);
    println!("Name: '{}'", name);
    println!("Labels count: {}", name.iter().count());
    for (i, label) in name.iter().enumerate() {
        println!("Label {}: '{}'", i, std::str::from_utf8(label.as_ref()).unwrap());
    }
}
