extern crate rustc_serialize;

use std::net::TcpStream;
use std::io::prelude::*;
use std::collections::HashMap;
use rustc_serialize::json;

pub struct WhoIs {
    server: String,
    follow: isize,
    new_whois: String,
    query: String
}

impl WhoIs {
    pub fn new(x: String)-> WhoIs {
        WhoIs {
            server: x,
            follow: 0,
            new_whois: String::new(),
            query: String::new()
        }
    }
    ///
    ///
    ///  This function will get whois server from the `get_server` function decide the appropriate
    ///  query for the server and parse the whois data into JSON by calling parse_data()
    ///  If there is another whois server in the whois data then it calls 'parse_whois'
    ///  so it can get the whois data from that
    ///
    pub fn lookup(&mut self) -> String {
        let mut result = String::new();
        let mut server = self.new_whois.to_owned();
        let target = self.server.to_owned();
        let tld = target.split(".").last().expect("Invalid URL?");
        if self.follow == 0 {
            self.query = match tld {
                "com" | "net" => "DOMAIN ".into(),
                _ => "".into()
            };
            server = self.get_server(&tld);
        }
        let mut client = TcpStream::connect((&*server, 43u16)).expect("Could not connect to server!!");
        match client.write_all(format!("{}{}\n", self.query, target).as_bytes()) {
            Ok(_) => (),
            Err(e) => panic!("Could not write to client {}", e)
        }
        client.read_to_string(&mut result).unwrap();
        if result.contains("Whois Server:") {
            self.query = "".into();
            self.follow += 1;                                             // If there is another Whois Server, take that server and pass it to
            return self.parse_whois(&*result)                             // pass it to parse_whois
        }
        else {
            let clean = result.replace("http:", "").replace("https:",""); // I'm splitting via ':' so the urls needs to be omitted
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
    ///
    /// This function calls lookup() again if there is a another whois server
    ///
    ///
    fn parse_whois(&mut self, result: &str) -> String {
        let line = &result.lines().find(|i| i.contains("Whois Server:")).unwrap();
        let target = line.split_whitespace().last().unwrap().to_owned();
        self.new_whois = target;
        self.lookup()
    }

    fn get_server(&self, target: &str) -> String {
        let mut result = String::new();
        let mut client = TcpStream::connect("whois.iana.org:43").expect("Could not connect to server!");
        match client.write_all(format!("{}\n", target).as_bytes()) {
            Ok(_) => (),
            Err(e) => panic!("Could not write to client {}", e)
        }
        client.read_to_string(&mut result).unwrap();
        let line = &result.lines().find(|i| i.starts_with("whois:")).unwrap();
        let foo = line.split_whitespace().last().unwrap().to_owned();
        foo
    }
}
