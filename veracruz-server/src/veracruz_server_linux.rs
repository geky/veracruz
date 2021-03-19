//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {
    use crate::veracruz_server::VeracruzServer;
    use crate::veracruz_server::VeracruzServerError;
    use veracruz_utils::{
        policy::EnclavePlatform, RuntimeManagerMessage, NitroStatus,
    };

    use std::process::{Command, Child};
    use std::net::TcpStream;
    use std::cell::RefCell;
    use std::sync::Mutex;

    const RUNTIME_MANAGER_PATH: &str = "../runtime-manager/target/release/runtime_manager_enclave";
    const RUNTIME_MANAGER_ADDR: &str = "127.0.0.1:5022";

    pub struct VeracruzServerLinux {
        child: Child,
        // TODO the use of refcell here is a hack for allowing a mutable type
        // an immutable type... in theory the below functions in the
        // VeracruzServer trait should take &mut self and this should not be
        // needed
        socket: Mutex<RefCell<TcpStream>>,
    }

    impl VeracruzServer for VeracruzServerLinux {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            // Set up, initialize Nitro Root Enclave
            let policy: veracruz_utils::VeracruzPolicy =
                veracruz_utils::VeracruzPolicy::from_json(policy_json)?;

            // TODO need to perform native attestation? figure out how
            // runtime_manager_hash fits together
//            {
//                let mut nre_guard = NRE_CONTEXT.lock()?;
//                if nre_guard.is_none() {
//                    println!("NITRO ROOT ENCLAVE IS UNINITIALIZED.");
//                    let runtime_manager_hash = policy
//                        .runtime_manager_hash(&EnclavePlatform::Nitro)
//                        .map_err(|err| VeracruzServerError::VeracruzUtilError(err))?;
//                    let nre_context =
//                        VeracruzServerNitro::native_attestation(&policy.proxy_attestation_server_url(), &runtime_manager_hash)?;
//                    *nre_guard = Some(nre_context);
//                }
//            }

            // launch process
            let mut child = Command::new(RUNTIME_MANAGER_PATH).spawn()?;
            println!("VeracruzServerLinux::new running runtime_manager child process as {:?}", child.id());

            // wait for process to spin up
            std::thread::sleep(std::time::Duration::from_millis(100));

            // create socket connected to child
            let socket = match TcpStream::connect(RUNTIME_MANAGER_ADDR) {
                Ok(socket) => socket,
                Err(err) => {
                    // need to kill child if this happens
                    let res_ = child.kill();
                    println!("VeracruzServerLinux::new failed to connect {:?}", err);
                    println!("VeracruzServerLinux::new killed child process {:?}", res_);
                    Err(err)?
                }
            };
            println!("VeracruzServerLinux::new connected to process at {:?}", RUNTIME_MANAGER_ADDR);

            let meta = Self {
                child: child,
                socket: Mutex::new(RefCell::new(socket))
            };

            // send initialization
            let initialize: RuntimeManagerMessage = RuntimeManagerMessage::Initialize(policy_json.to_string());
            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.receive_buffer()?;
            let message: RuntimeManagerMessage = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                RuntimeManagerMessage::Status(status) => status,
                _ => return Err(VeracruzServerError::RuntimeManagerMessageStatus(message)),
            };
            match status {
                NitroStatus::Success => (),
                _ => return Err(VeracruzServerError::NitroStatus(status)),
            }
            println!("VeracruzServerLinux::new complete. Returning");
            
            Ok(meta)
        }

        // Note: this function will go away
        fn get_enclave_cert(&self) -> Result<Vec<u8>, VeracruzServerError> {
            let certificate = {
                let message = RuntimeManagerMessage::GetEnclaveCert;
                let message_buffer = bincode::serialize(&message)?;
                self.send_buffer(&message_buffer)?;
                // Read the resulting data as the certificate
                let received_buffer = self.receive_buffer()?;
                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerMessage::EnclaveCert(cert) => cert,
                    _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message))?,
                }
            };
            return Ok(certificate);
        }

        // Note: This function will go away
        fn get_enclave_name(&self) -> Result<String, VeracruzServerError> {
            let name: String = {
                let message = RuntimeManagerMessage::GetEnclaveName;
                let message_buffer = bincode::serialize(&message)?;
                self.send_buffer(&message_buffer)?;
                // Read the resulting data as the name
                let received_buffer = self.receive_buffer()?;
                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerMessage::EnclaveName(name) => name,
                    _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
                }
            };
            return Ok(name);
        }

        fn plaintext_data(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            let parsed = transport_protocol::parse_runtime_manager_request(&data)?;

            if parsed.has_request_proxy_psa_attestation_token() {
                let rpat = parsed.get_request_proxy_psa_attestation_token();
                let challenge = transport_protocol::parse_request_proxy_psa_attestation_token(rpat);
                let (psa_attestation_token, pubkey, device_id) =
                    self.proxy_psa_attestation_get_token(challenge)?;
                let serialized_pat = transport_protocol::serialize_proxy_psa_attestation_token(
                    &psa_attestation_token,
                    &pubkey,
                    device_id,
                )?;
                Ok(Some(serialized_pat))
            } else {
                return Err(VeracruzServerError::InvalidProtoBufMessage);
            }
        }

        fn proxy_psa_attestation_get_token(
            &self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError> {
            // TODO 
            todo!();
//            let message = RuntimeManagerMessage::GetPSAAttestationToken(challenge);
//            let message_buffer = bincode::serialize(&message)?;
//            self.enclave.send_buffer(&message_buffer)?;
//
//            let received_buffer = self.enclave.receive_buffer()?;
//            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
//            let (token, public_key, device_id) = match received_message {
//                RuntimeManagerMessage::PSAAttestationToken(token, public_key, device_id) => {
//                    (token, public_key, device_id)
//                }
//                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
//            };
//            return Ok((token, public_key, device_id));
        }

        fn new_tls_session(&self) -> Result<u32, VeracruzServerError> {
            let nls_message = RuntimeManagerMessage::NewTLSSession;
            let nls_buffer = bincode::serialize(&nls_message)?;
            self.send_buffer(&nls_buffer)?;

            let received_buffer: Vec<u8> = self.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let session_id = match received_message {
                RuntimeManagerMessage::TLSSession(sid) => sid,
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            };
            return Ok(session_id);
        }

        fn close_tls_session(&self, session_id: u32) -> Result<(), VeracruzServerError> {
            let cts_message = RuntimeManagerMessage::CloseTLSSession(session_id);
            let cts_buffer = bincode::serialize(&cts_message)?;

            self.send_buffer(&cts_buffer)?;

            let received_buffer: Vec<u8> = self.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            return match received_message {
                RuntimeManagerMessage::Status(_status) => Ok(()),
                _ => Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
        }

        fn tls_data(
            &self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let std_message: RuntimeManagerMessage = RuntimeManagerMessage::SendTLSData(session_id, input);
            let std_buffer: Vec<u8> = bincode::serialize(&std_message)?;

            self.send_buffer(&std_buffer)?;

            let received_buffer: Vec<u8> = self.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            match received_message {
                RuntimeManagerMessage::Status(status) => match status {
                    NitroStatus::Success => (),
                    _ => return Err(VeracruzServerError::NitroStatus(status)),
                },
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            }

            let mut active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id)? {
                let gtd_message = RuntimeManagerMessage::GetTLSData(session_id);
                let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

                self.send_buffer(&gtd_buffer)?;

                let received_buffer: Vec<u8> = self.receive_buffer()?;

                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerMessage::TLSData(data, alive) => {
                        active_flag = alive;
                        ret_array.push(data);
                    }
                    _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
                }
            }

            Ok((
                active_flag,
                if ret_array.len() > 0 {
                    Some(ret_array)
                } else {
                    None
                },
            ))
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            fn request_reset(self_: &mut VeracruzServerLinux) -> Result<bool, VeracruzServerError> {
                let re_message: RuntimeManagerMessage = RuntimeManagerMessage::ResetEnclave;
                let re_buffer: Vec<u8> = bincode::serialize(&re_message)?;

                self_.send_buffer(&re_buffer)?;

                let received_buffer: Vec<u8> = self_.receive_buffer()?;
                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                return match received_message {
                    RuntimeManagerMessage::Status(status) => match status {
                        NitroStatus::Success => Ok(true),
                        _ => Err(VeracruzServerError::NitroStatus(status)),
                    },
                    _ => Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
                };
            }

            let res = request_reset(self);
            println!("VeracruzServerNitro::close requested reset");

            let res_ = self.socket.lock().unwrap().borrow_mut().shutdown(std::net::Shutdown::Both);
            println!("VeracruzServerNitro::close shutdown socket {:?}", res_);

            // always make sure to kill child, even if failure
            let res_ = self.child.kill();
            println!("VeracruzServerNitro::close killed child process {:?}", res_);

            res
        }
    }

    impl VeracruzServerLinux {
        // len+buffer send recv
        fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), VeracruzServerError> {
            Ok(veracruz_utils::send_buffer(&mut *self.socket.lock().unwrap().borrow_mut(), buffer)?)
        }

        fn receive_buffer(&self) -> Result<Vec<u8>, VeracruzServerError> {
            Ok(veracruz_utils::receive_buffer(&mut *self.socket.lock().unwrap().borrow_mut())?)
        }

        // tls management
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, VeracruzServerError> {
            let gtdn_message = RuntimeManagerMessage::GetTLSDataNeeded(session_id);
            let gtdn_buffer: Vec<u8> = bincode::serialize(&gtdn_message)?;

            self.send_buffer(&gtdn_buffer)?;

            let received_buffer: Vec<u8> = self.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let tls_data_needed = match received_message {
                RuntimeManagerMessage::TLSDataNeeded(needed) => needed,
                _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
            return Ok(tls_data_needed);
        }
    }

    impl Drop for VeracruzServerLinux {
        fn drop(&mut self) {
            println!("drop called");
            // try to forcefully kill our child
            match self.close() {
                Err(err) => println!("VeracruzServerLinux::drop failed in call to self.close:{:?}, we will persevere, though.", err),
                _ => (),
            }
        }
    }
}
