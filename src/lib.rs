extern crate rustc_serialize;

use std::net::TcpStream;
use std::io::prelude::*;
use std::collections::HashMap;
use rustc_serialize::json;

pub struct WhoIs {
    server: String,
}

impl WhoIs {
    pub fn new(x: String)-> WhoIs {
        WhoIs {
            server: x
        }
    }
    pub fn lookup(&mut self) -> String {
        let mut result = String::new();
        let target = self.server.to_owned();
        let tld = target.split(".").last().expect("nope");
        let query = match tld {
            "com" | "net" => "DOMAIN",
            _ => ""
        };
        let server = self.get_server(&tld);
        let mut client = TcpStream::connect((&*server, 43u16)).expect("Could not connect to server!!");
        match client.write_all(format!("{} {}\n", query, target).as_bytes()) {
            Ok(_) => (),
            Err(e) => panic!("Could not write to client {}", e)
        }
        client.read_to_string(&mut result).unwrap();
        if result.contains("Whois Server:") {
            return self.lookup2(&*result)
        }
        else {
            let clean = result.replace("http:", "").replace("https:","");
            return self.parse_data(clean)
        }
    }
    fn parse_data(&self, result: String) -> String {
        let mut data = HashMap::new();
        for c in result.lines() {
            let mut line = c.split(':');
            let key = line.next().unwrap();
            let value = match line.next() {
                Some(value) => value,
                None => continue
            };
            data.insert(key, value.trim());
        }
        return json::encode(&data).unwrap()
    }

    fn lookup2(&mut self, result: &str) -> String {
        let mut result2 = String::new();
        let line = &result.lines().find(|i| i.contains("Whois Server:")).expect("not found");
        let target = line.split_whitespace().last().unwrap().to_owned();
        let mut client = TcpStream::connect((&*target, 43u16)).expect("Could not connect to server!!");
        match client.write_all(format!("{}\n", self.server).as_bytes()) {
            Ok(_) => (),
            Err(e) => panic!("Could not write to client {}", e)
        }
        client.read_to_string(&mut result2).unwrap();
        let clean = result2.replace("http:", "").replace("https:","");
        self.parse_data(clean)
    }

    fn get_server(&self, target: &str) -> String {   //this will give me verisign-grs
        let mut result = String::new();
        let mut client = TcpStream::connect("whois.iana.org:43").expect("Could not connect to server!");
        match client.write_all(format!("{}\n", target).as_bytes()) {
            Ok(_) => (),
            Err(e) => panic!("Could not write to client {}", e)
        }
        client.read_to_string(&mut result).unwrap();
        let line = &result.lines().find(|i| i.starts_with("whois:")).unwrap();
        let foo = line.split_whitespace().last().unwrap().to_owned();
        //println!("{}", foo);
        foo
    }
}
