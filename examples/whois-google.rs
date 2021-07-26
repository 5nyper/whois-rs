extern crate whois;
extern crate rustc_serialize;

use whois::WhoIs;
use rustc_serialize::json::Json;

fn main() {
    let data = WhoIs::new("google.com").lookup();
    let foo = &Json::from_str(&data.unwrap()).unwrap();
    let object = foo.as_object().unwrap();
    for (key, value) in object {
        let value = match value {
            Json::String(ref v) => format!("{}", v),
            _ => break,
        };
        println!("{}: {}", key, value);
    }
}
