use std::{
    collections::{HashMap, HashSet},
    net::TcpListener,
};

pub(crate) struct PortBinder {
    ports: HashMap<u16, TcpListener>,
}

impl PortBinder {
    pub fn new() -> Self {
        PortBinder {
            ports: HashMap::new(),
        }
    }

    pub fn bind_port(&mut self, port: u16) -> Result<(), String> {
        if self.ports.contains_key(&port) {
            return Err(format!("Port {} is already bound", port));
        }

        let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();

        self.ports.insert(port, listener);

        Ok(())
    }
}
