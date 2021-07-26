#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;

extern crate rustc_serialize;

use std::net::TcpStream;
use std::io::prelude::*;
use std::collections::HashMap;
use rustc_serialize::json;

pub mod errors;
use errors::*;

pub struct WhoIs<'a> {
    server: &'a str,
    follow: isize,
    new_whois: String,
    query: String,
}

impl<'a> WhoIs<'a> {
    pub fn new(x: &'a str) -> WhoIs<'a> {
        WhoIs {
            server: x,
            follow: 0,
            new_whois: String::new(),
            query: String::new(),
        }
    }
    ///  This function will get whois server from the `get_server` function, decide the appropriate
    ///  query for the server and parse the whois data into JSON by calling `parse_data()`.
    ///
    ///  If there is another whois server in the whois data then it calls `parse_whois`,
    ///  so it can get the whois data from that.
    pub fn lookup(&mut self) -> Result<String> {
        let mut result = String::new();
        let mut server = self.new_whois.to_owned();
        let target = self.server.to_owned();
        let tld = match target.split(".").last() {
            Some(tld) => tld,
            None => return Err("Invalid URL?".into()),
        };
        if self.follow == 0 {
            self.query = match tld {
                "com" | "net" => "DOMAIN ".into(),
                _ => "".into(),
            };
            server = self.get_server(&tld).expect(&format!("Failed to get server for {}", tld));
        }
        let mut client = TcpStream::connect((&*server, 43u16))
                            .chain_err(|| "Could not connect to server!!")?;

        client.write_all(format!("{}{}\n", self.query, target).as_bytes())
            .chain_err(|| "Could not write to client {}")?;

        client.read_to_string(&mut result)
            .chain_err(|| "Failed to read to string")?;

        if result.contains("Whois Server:") {
            self.query = "".into();
            self.follow += 1; // If there is another Whois Server, take that server and pass it to.
            Ok(self.parse_whois(&*result)) // Pass it to parse_whois.
        } else {
            let clean = result.replace("http:", "").replace("https:", ""); // I'm splitting via ':' so the urls' protocols needs to be omitted.
            self.parse_data(clean)
        }
    }
    fn parse_data(&self, result: String) -> Result<String> {
        let mut data = HashMap::new();
        for c in result.lines() {
            let mut line = c.split(':');
            let key = line.next().expect("Failed to get key");
            let value = match line.next() {
                Some(value) => value,
                None => continue,
            };
            data.insert(key, value.trim());
        }
        json::encode(&data).chain_err(|| "Could not encode data as json")
    }

    /// This function calls `lookup()` again if there is a another whois server.
    fn parse_whois(&mut self, result: &str) -> String {
        let line = &result.lines()
                          .find(|i| i.contains("Whois Server:"))
                          .expect("Could not find wh");
        let target = line.split_whitespace().last().unwrap().to_owned();
        self.new_whois = target;
        self.lookup().expect("Failed lookup in parse_whois")
    }

    fn get_server(&self, target: &str) -> Result<String> {
        let mut result = String::new();
        let mut client = TcpStream::connect("whois.iana.org:43")
                                .chain_err(|| "Could not connect to server!")?;

        client.write_all(format!("{}\n", target).as_bytes())
            .chain_err(|| "Could not write to client")?;

        client.read_to_string(&mut result).chain_err(|| "Failed to read result to string")?;
        let line = &result.lines().find(|i| i.starts_with("whois:")).expect("Couldnt get wh");
        let foo = line.split_whitespace().last().unwrap().to_owned();
        Ok(foo)
    }
}
