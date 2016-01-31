# whois-rs [![Build status](https://api.travis-ci.org/Vikaton/whois-rs.svg?branch=master)](https://travis-ci.org/Vikaton/whois-rs)
a whois client library, inspired by https://github.com/hjr265/node-whois

#Example

```rust
extern crate whois;
extern crate rustc_serialize;

use whois::WhoIs;
use rustc_serialize::json::Json;

fn main() {
    let data = WhoIs::new("google.com".to_owned()).lookup();  //get data in JSON format
    let foo = &Json::from_str(&data).unwrap();                //decode JSON
    let object = foo.as_object().unwrap();                    //convert it into a BTreeMap
    for (key, value) in object {
        println!("{}: {}", key, match *value {
            Json::String(ref v) => format!("{}", v),
            _ => break
        });
    }
}
```

#TODO
- [ ] Error-Handling and WHOIS server following
