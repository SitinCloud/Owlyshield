//! A JSON-RPC HTTP server that may be used for interfacing with third-party products. For example, it may
//! be used by Telegraf to save activity data in `InfluxDB`.
//! Compile with `--feature jsonrpc`.
//!
//! It listens on `localhost:3030` and only provides two methods
//! - `ping`: to check it works
//! - `last_prediction`: which returns the map of the last registered [`crate::prediction::input_tensors::Timestep`].
//!
//! Exemple of call:
//! ```curl -X POST \
//!   http://127.0.0.1:3030/ \
//!   -H 'content-type: application/json' \
//!   -d '{
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "last_prediction",
//!     "params": []
//! }'
//! ```
use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use jsonrpc_http_server::jsonrpc_core::IoHandler;
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use serde_json::{Number, Value};
use serde::Serialize;
use crate::predictions::prediction::input_tensors::Timestep;

#[derive(Debug, Clone, Serialize)]
pub struct RPCMessage {
    pub appname: String,
    pub timestep: Timestep,
}

pub struct Jsonrpc {
    rx: Receiver<RPCMessage>,
    rpcmsg: Arc<Mutex<HashMap<String, RPCMessage>>>
}

impl RPCMessage {
    pub fn from(appname: String, timestep: Timestep) -> RPCMessage {
        RPCMessage {
            appname,
            timestep
        }
    }
}

impl Jsonrpc {
    pub fn from(rx: Receiver<RPCMessage>) -> Jsonrpc {
        Jsonrpc {
            rx,
            rpcmsg: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn jsonvec(rpcmsg: Arc<Mutex<HashMap<String, RPCMessage>>>) -> Vec<Value> {
        let mut res = vec![];
        for v in (*rpcmsg.lock().unwrap()).values() {
            let mut kmap = serde_json::Map::new();
            kmap.insert(String::from("appname"), Value::String(v.appname.clone()));
            kmap.insert(String::from("ops_read"), Value::Number(Number::from(v.timestep.ops_read)));
            kmap.insert(String::from("ops_setinfo"), Value::Number(Number::from(v.timestep.ops_setinfo)));
            kmap.insert(String::from("ops_written"), Value::Number(Number::from(v.timestep.ops_written)));
            kmap.insert(String::from("ops_open"), Value::Number(Number::from(v.timestep.ops_open)));
            kmap.insert(String::from("bytes_read"), Value::Number(Number::from(v.timestep.bytes_read)));
            kmap.insert(String::from("bytes_written"), Value::Number(Number::from(v.timestep.bytes_written)));
            kmap.insert(String::from("entropy_read"), Value::Number(Number::from_f64(v.timestep.entropy_read as f64).unwrap()));
            kmap.insert(String::from("entropy_written"), Value::Number(Number::from_f64(v.timestep.entropy_written as f64).unwrap()));
            kmap.insert(String::from("files_opened"), Value::Number(Number::from(v.timestep.files_opened)));
            kmap.insert(String::from("files_deleted"), Value::Number(Number::from(v.timestep.files_deleted)));
            kmap.insert(String::from("files_read"), Value::Number(Number::from(v.timestep.files_read)));
            kmap.insert(String::from("files_renamed"), Value::Number(Number::from(v.timestep.files_renamed)));
            kmap.insert(String::from("files_written"), Value::Number(Number::from(v.timestep.files_written)));
            kmap.insert(String::from("extensions_read"), Value::Number(Number::from(v.timestep.extensions_read)));
            kmap.insert(String::from("extensions_written"), Value::Number(Number::from(v.timestep.extensions_written)));
            kmap.insert(String::from("extensions_written_doc"), Value::Number(Number::from(v.timestep.extensions_written_doc)));
            kmap.insert(String::from("extensions_written_archives"), Value::Number(Number::from(v.timestep.extensions_written_archives)));
            kmap.insert(String::from("extensions_written_db"), Value::Number(Number::from(v.timestep.extensions_written_db)));
            kmap.insert(String::from("extensions_written_code"), Value::Number(Number::from(v.timestep.extensions_written_code)));
            kmap.insert(String::from("extensions_written_exe"), Value::Number(Number::from(v.timestep.extensions_written_exe)));
            kmap.insert(String::from("dirs_with_files_created"), Value::Number(Number::from(v.timestep.dirs_with_files_created)));
            kmap.insert(String::from("dirs_with_files_updated"), Value::Number(Number::from(v.timestep.dirs_with_files_updated)));
            kmap.insert(String::from("pids"), Value::Number(Number::from(v.timestep.  pids)));
            kmap.insert(String::from("exe_exists"), Value::Bool(v.timestep.exe_exists));
            kmap.insert(String::from("clusters"), Value::Number(Number::from(v.timestep.cluster_count)));
            kmap.insert(String::from("clusters_max_size"), Value::Number(Number::from(v.timestep. clusters_max_size)));
            kmap.insert(String::from("alters_email_file"), Value::Bool(v.timestep.alters_email_file));
            kmap.insert(String::from("password_vault_read_count"), Value::Number(Number::from(v.timestep.password_vault_read_count)));
            kmap.insert(String::from("alters_event_log_file"), Value::Bool(v.timestep.alters_event_log_file));
            kmap.insert(String::from("alters_ssh_file"), Value::Bool(v.timestep.alters_ssh_file));
            kmap.insert(String::from("on_shared_drive_read_count"), Value::Number(Number::from(v.timestep.on_shared_drive_read_count)));
            kmap.insert(String::from("on_shared_drive_write_count"), Value::Number(Number::from(v.timestep.on_shared_drive_write_count)));
            kmap.insert(String::from("on_removable_drive_read_count"), Value::Number(Number::from(v.timestep.on_removable_drive_read_count)));
            kmap.insert(String::from("on_removable_drive_write_count"), Value::Number(Number::from(v.timestep.on_removable_drive_write_count)));
            kmap.insert(String::from("time"), Value::String(Utc::now().to_rfc3339()));
            res.push(Value::Object(kmap));
        }
        res
    }

    pub fn start_server(&mut self) {
        let rpcmsg = Arc::clone(&self.rpcmsg);
        let mut io = IoHandler::default();
        io.add_sync_method("last_prediction", move|_| {
            let res = Self::jsonvec(rpcmsg.clone());
            rpcmsg.lock().unwrap().clear();
            Ok(Value::Array(res))
        });

        io.add_sync_method("ping", move|_| {
           Ok(Value::String(String::from("pong")))
        });

        let _server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Any]))
            .start_http(&"127.0.0.1:3030".parse().unwrap())
            .expect("Unable to start RPC server");

        self.process();
    }

    pub fn process(&mut self) {
        loop {
            let msg = self.rx.recv().unwrap();
            let mut a = self.rpcmsg.lock().unwrap();
            a.insert(msg.appname.clone(), msg);
        }
    }
}