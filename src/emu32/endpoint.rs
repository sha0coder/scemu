//TODO: support multiple sockets

use std::net::TcpStream;
use std::net::Shutdown;
use std::io::Write;
use std::io::Read;
use lazy_static::lazy_static; 
use std::sync::Mutex;


lazy_static! {
    static ref STREAM:Mutex<Vec<TcpStream>> = Mutex::new(Vec::new());
}

pub fn warning() {
    print!("/!\\ is your VPN or Tor ready (y/n) ?");
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

pub fn sock_connect(host:&str, port:u16) -> bool {
    let mut stream = STREAM.lock().unwrap();
    println!("\tconnecting to {}:{}...", host, port);
    stream.push(match TcpStream::connect((host, port)) {
        Ok(s) => s, 
        Err(_) => { return false; }
    });
    println!("\tconnected!");
    return true;
}

pub fn sock_send(buffer:&[u8]) -> usize {
    let mut stream = STREAM.lock().unwrap();
    let n = match stream[0].write(buffer) {
        Ok(w) => w,
        Err(_) => 0,
    };
    return n;
}

pub fn sock_recv(buffer:&mut [u8]) -> usize {
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
        Ok(_)  => {}
        Err(_) => {}
    }
    stream.clear();
}

