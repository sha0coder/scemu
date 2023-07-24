/*
    TODO:
        - support multiple sockets
        - support post
        - wide apis
*/

extern crate attohttpc;

use attohttpc::header;
use attohttpc::RequestBuilder;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpStream;
use std::sync::Mutex;

lazy_static! {
    static ref STREAM: Mutex<Vec<TcpStream>> = Mutex::new(Vec::new());
    static ref HTTP_HDRS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref HTTP_SERVER: Mutex<String> = Mutex::new(String::new());
    static ref HTTP_PORT: Mutex<u16> = Mutex::new(0);
    static ref HTTP_PATH: Mutex<String> = Mutex::new(String::new());
    static ref HTTP_SSL: Mutex<bool> = Mutex::new(false);
    static ref HTTP_METHOD: Mutex<String> = Mutex::new(String::new());
    static ref HTTP_DATA: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}

pub fn warning() {
    print!("/!\\ is your VPN or Tor ready (y/n)? ");
    std::io::stdout().flush().unwrap();

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).unwrap();
    answer = answer.replace("\r", ""); // some shells (windows) also add \r  thanks Alberto Segura
    answer.truncate(answer.len() - 1);
    let lanswer = answer.to_lowercase();
    if lanswer != "y" && lanswer != "yes" {
        std::process::exit(1);
    }
}

pub fn sock_connect(host: &str, port: u16) -> bool {
    let mut stream = STREAM.lock().unwrap();
    println!("\tconnecting to {}:{}...", host, port);
    stream.push(match TcpStream::connect((host, port)) {
        Ok(s) => s,
        Err(_) => {
            return false;
        }
    });
    println!("\tconnected!");
    return true;
}

pub fn sock_send(buffer: &[u8]) -> usize {
    let mut stream = STREAM.lock().unwrap();
    let n = match stream[0].write(buffer) {
        Ok(w) => w,
        Err(_) => 0,
    };
    return n;
}

pub fn sock_recv(buffer: &mut [u8]) -> usize {
    let mut stream = STREAM.lock().unwrap();
    let n = match stream[0].read(buffer) {
        Ok(r) => r,
        Err(_) => 0,
    };
    return n;
}

pub fn sock_close() {
    let mut stream = STREAM.lock().unwrap();
    match stream[0].shutdown(Shutdown::Both) {
        Ok(_) => {}
        Err(_) => {}
    }
    stream.clear();
}

pub fn http_set_method(meth: &str) {
    let mut method = HTTP_METHOD.lock().unwrap();
    *method = meth.to_string().to_lowercase();
}

pub fn http_set_serverport(host: &str, port: u16) {
    let mut mhost = HTTP_SERVER.lock().unwrap();
    *mhost = host.to_string();

    let mut mport = HTTP_PORT.lock().unwrap();
    *mport = port;
}

pub fn http_set_headers(key: &str, value: &str) {
    let mut headers = HTTP_HDRS.lock().unwrap();
    headers.insert(
        key.to_string().replace("\r", "").replace("\n", ""),
        value.to_string().replace("\r", "").replace("\n", ""),
    );
}

pub fn http_set_headers_str(hdrs: &str) {
    let mut headers = HTTP_HDRS.lock().unwrap();

    let lines: Vec<&str> = hdrs.split("\n").collect();
    for l in lines.iter() {
        let cols: Vec<&str> = l.split(": ").collect();
        if cols.len() == 2 {
            headers.insert(
                cols[0].to_string().replace("\r", "").replace("\n", ""),
                cols[1].to_string().replace("\r", "").replace("\n", ""),
            );
        }
    }
}

pub fn http_set_path(ppath: &str) {
    let mut path = HTTP_PATH.lock().unwrap();
    *path = ppath.to_string();
}

pub fn http_set_ssl() {
    let mut ssl = HTTP_SSL.lock().unwrap();
    *ssl = true;
}

pub fn http_send_request() {
    let host = HTTP_SERVER.lock().unwrap();
    let port = HTTP_PORT.lock().unwrap();
    let path = HTTP_PATH.lock().unwrap();
    let https = HTTP_SSL.lock().unwrap();
    let hdrs = HTTP_HDRS.lock().unwrap();
    let method = HTTP_METHOD.lock().unwrap();
    let mut data = HTTP_DATA.lock().unwrap();

    let url: String;

    if *https {
        url = format!("https://{}:{}{}", host, port, path);
    } else {
        url = format!("http://{}:{}{}", host, port, path);
    }

    println!("\tconnecting to url: {}", url);

    let mut req: RequestBuilder = match method.as_str() {
        "get" => attohttpc::get(url),
        "post" => attohttpc::post(url),
        "head" => attohttpc::head(url),
        "delete" => attohttpc::delete(url),
        "options" => attohttpc::options(url),
        "patch" => attohttpc::patch(url),
        "trace" => attohttpc::trace(url),
        _ => {
            println!("\tweird method.");
            return;
        }
    };

    req = req.danger_accept_invalid_hostnames(true);
    req = req.danger_accept_invalid_certs(true);

    for k in hdrs.keys() {
        let key = k.clone();
        let v = &hdrs[&key];
        let hn: header::HeaderName =
            match header::HeaderName::from_bytes(&key.to_lowercase().as_bytes()) {
                Ok(h) => h,
                Err(e) => {
                    println!("\terror in header {}  err: {}", &key, e);
                    return;
                }
            };
        //println!("\tadding header: `{}` value: `{}`", &key, &v);
        req = req
            .try_header_append::<header::HeaderName, &str>(hn, &v)
            .expect("cannot add header");
    }

    let resp = match req.send() {
        Ok(r) => r,
        Err(_) => {
            println!("\tCannot connect.");
            return;
        }
    };

    if resp.is_success() {
        *data = resp.bytes().expect("error receiving data");
        println!("\t{} bytes downloaded", data.len());
    } else {
        println!("\tURL not Ok.");
    }
}

pub fn http_read_data() -> Vec<u8> {
    let mut data = HTTP_DATA.lock().unwrap();
    let r = &*data.clone();
    data.clear();
    return r.to_vec();
}
