use lazy_static::lazy_static;
use std::sync::Mutex;

pub struct Handler {
    id: u64,
    uri: String,
    data: Vec<u8>,
}

impl Handler {
    fn new(id: u64, uri: &str) -> Handler {
        Handler {
            id,
            uri: uri.to_string(),
            data: vec![],
        }
    }
}

lazy_static! {
    static ref HANDLERS: Mutex<Vec<Handler>> = Mutex::new(Vec::new());
    static ref SOCKETS: Mutex<Vec<u64>> = Mutex::new(vec![0; 0]);
}

pub fn handler_create(uri: &str) -> u64 {
    let mut handles = HANDLERS.lock().unwrap();

    let new_id: u64 = if handles.len() == 0 {
        1
    } else {
        let last_id = handles[handles.len() - 1].id;
        last_id + 1
    };

    let new_handler = Handler::new(new_id, uri);

    handles.push(new_handler);
    new_id
}

pub fn handler_close(hndl: u64) -> bool {
    let mut handles = HANDLERS.lock().unwrap();
    let idx = match handles.iter().position(|h| h.id == hndl) {
        Some(i) => i,
        None => return false,
    };
    handles.remove(idx);
    true
}

pub fn handler_print() {
    let hndls = HANDLERS.lock().unwrap();
    for h in hndls.iter() {
        log::info!("{:x} {}", h.id, h.uri);
    }
}

pub fn handler_exist(hndl: u64) -> bool {
    let handles = HANDLERS.lock().unwrap();
    match handles.iter().position(|h| h.id == hndl) {
        Some(_) => true,
        None => false,
    }
}

pub fn handler_put_bytes(hndl: u64, data: &[u8]) {
    let mut handles = HANDLERS.lock().unwrap();
    match handles.iter().position(|h| h.id == hndl) {
        Some(idx) => handles[idx].data = data.to_vec(),
        None => (),
    }
}

pub fn handler_get_uri(hndl: u64) -> String {
    let handles = HANDLERS.lock().unwrap();
    match handles.iter().position(|h| h.id == hndl) {
        Some(idx) => handles[idx].uri.clone(),
        None => String::new(),
    }
}

pub fn socket_create() -> u64 {
    let mut sockets = SOCKETS.lock().unwrap();

    let new_socket: u64 = if sockets.len() == 0 {
        sockets.push(0); // stdin
        sockets.push(1); // stdout
        sockets.push(2); // stderr
        3 // first available socket
    } else {
        let last_socket = sockets[sockets.len() - 1];
        last_socket + 1
    };

    sockets.push(new_socket);
    new_socket
}

pub fn socket_close(sock: u64) -> bool {
    let mut sockets = SOCKETS.lock().unwrap();
    let idx = match sockets.iter().position(|s| *s == sock) {
        Some(i) => i,
        None => return false,
    };
    sockets.remove(idx);
    true
}

pub fn socket_exist(sock: u64) -> bool {
    let sockets = SOCKETS.lock().unwrap();
    match sockets.iter().position(|s| *s == sock) {
        Some(_) => true,
        None => false,
    }
}
