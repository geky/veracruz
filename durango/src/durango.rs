//! The Durango library
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::{attestation::Attestation, error::DurangoError};
use ring::signature::KeyPair;
use rustls::Session;
use std::{
    path,
    io::{Read, Write},
    str::from_utf8,
};
use veracruz_utils::{VeracruzPolicy, VeracruzRole};
use webpki;
use webpki_roots;

#[cfg(not(feature = "mock"))]
use crate::attestation::AttestationPSA as AttestationHandler;

// Use Mockall for testing
#[cfg(feature = "mock")]
use crate::attestation::MockAttestation as AttestationHandler;

#[derive(Debug)]
pub struct Durango {
    tls_session: rustls::ClientSession,
    remote_session_id: Option<u32>,
    policy: VeracruzPolicy,
    policy_hash: String,
    package_id: u32,
    client_cert: String,
}

impl Durango {
    /// Provide file path.
    /// Read all the bytes in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_all_bytes_in_file<P>(filename: P) -> Result<Vec<u8>, DurangoError>
    where
        P: AsRef<path::Path>
    {
        let mut file = std::fs::File::open(filename)?;
        let mut buffer = std::vec::Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Provide file path.
    /// Read the certificate in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    // TODO: use generic functions to unify read_cert and read_private_key
    fn read_cert<P>(filename: P) -> Result<rustls::Certificate, DurangoError>
    where
        P: AsRef<path::Path>
    {
        let buffer = Durango::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let cert_vec = rustls::internal::pemfile::certs(&mut cursor)
            .map_err(|_| DurangoError::TLSUnspecifiedError)?;
        if cert_vec.len() == 1 {
            Ok(cert_vec[0].clone())
        } else {
            Err(DurangoError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// Provide file path.
    /// Read the private in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_private_key<P>(filename: P) -> Result<rustls::PrivateKey, DurangoError>
    where
        P: AsRef<path::Path>
    {
        let buffer = Durango::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let pkey_vec = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
            .map_err(|_| DurangoError::TLSUnspecifiedError)?;
        if pkey_vec.len() == 1 {
            Ok(pkey_vec[0].clone())
        } else {
            Err(DurangoError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// Initialise self signed certificate client config
    /// Set up the ciphersuite
    fn init_self_signed_cert_client_config(
        client_cert: rustls::Certificate,
        client_priv_key: rustls::PrivateKey,
        enclave_cert_hash: Vec<u8>,
        _enclave_name: &str,
        ciphersuite_string: &str,
    ) -> Result<rustls::ClientConfig, DurangoError> {
        let mut client_config = rustls::ClientConfig::new_self_signed();

        let client_cert_vec = vec![client_cert];
        client_config.set_single_client_cert(client_cert_vec, client_priv_key);

        client_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        client_config
            .pinned_cert_hashes
            .push(enclave_cert_hash.to_vec());

        // Set the client's supported ciphersuite to the one specified in the policy
        client_config.ciphersuites.clear();

        Self::set_up_client_ciphersuite(client_config, ciphersuite_string)
    }

    /// If ``ciphersuite_string`` is a supported cipher suite,
    /// add it into ``client_config``.
    /// Otherwise return error message.
    fn set_up_client_ciphersuite(
        mut client_config: rustls::ClientConfig,
        ciphersuite_string: &str,
    ) -> Result<rustls::ClientConfig, DurangoError> {
        client_config.ciphersuites.clear();

        let policy_ciphersuite =
            rustls::CipherSuite::lookup_value(ciphersuite_string).map_err(|_| {
                DurangoError::TLSInvalidCyphersuiteError(ciphersuite_string.to_string())
            })?;
        let supported_ciphersuite = rustls::ALL_CIPHERSUITES
            .iter()
            .fold(None, |last_rst, avalabie| {
                last_rst.or(if avalabie.suite == policy_ciphersuite {
                    Some(avalabie)
                } else {
                    None
                })
            })
            .ok_or(DurangoError::TLSUnsupportedCyphersuiteError(
                policy_ciphersuite,
            ))?;
        client_config.ciphersuites.push(supported_ciphersuite);
        Ok(client_config)
    }

    /// Check the validity of client_cert:
    /// parse the certificate and match it with the public key generated from the private key;
    /// check if the certificate is valid in term of time.
    fn check_certificate_validity<P>(
        client_cert_filename: P,
        public_key: &[u8],
    ) -> Result<(), DurangoError>
    where
        P: AsRef<path::Path>
    {
        let cert_file = std::fs::File::open(&client_cert_filename)?;
        let parsed_cert = x509_parser::pem::Pem::read(std::io::BufReader::new(cert_file))?;
        let parsed_cert = parsed_cert
            .0
            .parse_x509()
            .map_err(|e| DurangoError::X509ParserError(e.to_string()))?
            .tbs_certificate;

        if parsed_cert.subject_pki.subject_public_key.data != public_key {
            Err(DurangoError::MismatchError {
                variable: "public_key",
                expected: parsed_cert.subject_pki.subject_public_key.data.to_vec(),
                received: public_key.to_vec(),
            })
        } else if let None = parsed_cert.validity.time_to_expiration() {
            Err(DurangoError::CertificateExpireError(
                client_cert_filename.as_ref().to_string_lossy().to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Load the client certificate and key, and the global policy, which contains information
    /// about the enclave.
    /// Attest the enclave.
    pub fn new<P1, P2>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy_json: &str,
    ) -> Result<Durango, DurangoError>
    where
        P1: AsRef<path::Path>,
        P2: AsRef<path::Path>
    {
        let policy_hash = hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            policy_json.as_bytes(),
        ));
        let policy = veracruz_utils::VeracruzPolicy::from_json(&policy_json)?;

        Self::with_policy_and_hash(
            client_cert_filename,
            client_key_filename,
            policy,
            policy_hash,
        )
    }

    /// Load the client certificate and key, and the global policy, which contains information
    /// about the enclave. This takes the global policy as a VeracruzPolicy struct and
    /// related hash.
    /// Attest the enclave.
    pub fn with_policy_and_hash<P1, P2>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy: VeracruzPolicy,
        policy_hash: String,
    ) -> Result<Durango, DurangoError>
    where
        P1: AsRef<path::Path>,
        P2: AsRef<path::Path>
    {
        let client_cert = Self::read_cert(&client_cert_filename)?;
        let client_priv_key = Self::read_private_key(&client_key_filename)?;

        // check if the certificate is valid
        let key_pair = ring::signature::RsaKeyPair::from_der(client_priv_key.0.as_slice())?;
        Self::check_certificate_validity(&client_cert_filename, key_pair.public_key().as_ref())?;

        let (enclave_cert_hash, enclave_name) = AttestationHandler::attestation(&policy)?;

        let policy_ciphersuite_string = policy.ciphersuite().as_str();

        let client_config = Self::init_self_signed_cert_client_config(
            client_cert,
            client_priv_key,
            enclave_cert_hash,
            &enclave_name,
            policy_ciphersuite_string,
        )?;
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(&enclave_name)?;
        let session = rustls::ClientSession::new(&std::sync::Arc::new(client_config), dns_name);
        let client_cert_text = Durango::read_all_bytes_in_file(&client_cert_filename)?;
        let mut client_cert_raw = from_utf8(client_cert_text.as_slice())?.to_string();
        // erase some '\n' to match the format in policy file.
        client_cert_raw.retain(|c| c != '\n');
        let client_cert_string = client_cert_raw
            .replace(
                "-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\n",
            )
            .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");

        Ok(Durango {
            tls_session: session,
            remote_session_id: None,
            policy: policy,
            policy_hash: policy_hash,
            package_id: 0,
            client_cert: client_cert_string,
        })
    }

    fn check_role_permission(&self, role: &VeracruzRole) -> Result<(), DurangoError> {
        match self
            .policy
            .identities()
            .iter()
            .find(|&x| *x.certificate() == self.client_cert)
        {
            Some(identity) => match identity.roles().iter().find(|&x| *x == *role) {
                Some(_) => Ok(()),
                None => Err(DurangoError::InvalidRoleError(
                    self.client_cert.clone().into_bytes(),
                    role.clone(),
                )),
            },
            None => Err(DurangoError::InvalidClientCertificateError(
                self.client_cert.to_string(),
            )),
        }
    }

    pub fn send_program(&mut self, program: &Vec<u8>) -> Result<(), DurangoError> {
        self.check_role_permission(&VeracruzRole::PiProvider)?;

        self.check_policy_hash()?;

        let serialized_program = colima::serialize_program(&program)?;
        let response = self.send(&serialized_program)?;
        let parsed_response = colima::parse_mexico_city_response(&response)?;
        let status = parsed_response.get_status();
        match status {
            colima::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(DurangoError::ResponseError("send_program", status));
            }
        }
    }

    pub fn send_data(&mut self, data: &Vec<u8>) -> Result<(), DurangoError> {
        self.check_role_permission(&VeracruzRole::DataProvider)?;
        self.check_policy_hash()?;
        self.check_pi_hash()?;
        let serialized_data = colima::serialize_program_data(&data, self.next_package_id())?;
        let response = self.send(&serialized_data)?;

        let parsed_response = colima::parse_mexico_city_response(&response)?;
        let status = parsed_response.get_status();
        match status {
            colima::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(DurangoError::ResponseError("send_data", status));
            }
        }
    }

    pub fn get_results(&mut self) -> Result<Vec<u8>, DurangoError> {
        self.check_role_permission(&VeracruzRole::ResultReader)?;
        self.check_policy_hash()?;
        self.check_pi_hash()?;

        let serialized_read_result = colima::serialize_request_result()?;
        let response = self.send(&serialized_read_result)?;

        let parsed_response = colima::parse_mexico_city_response(&response)?;
        let status = parsed_response.get_status();
        if status != colima::ResponseStatus::SUCCESS {
            return Err(DurangoError::ResponseError("get_result", status));
        }
        if !parsed_response.has_result() {
            return Err(DurangoError::SinaloaResponseNoResultError);
        }
        let response_data = &parsed_response.get_result().data;
        return Ok(response_data.clone());
    }

    pub fn request_shutdown(&mut self) -> Result<(), DurangoError> {
        let serialized_request = colima::serialize_request_shutdown()?;
        let _response = self.send(&serialized_request)?;
        Ok(())
    }

    fn next_package_id(&mut self) -> u32 {
        let rst = self.package_id;
        self.package_id += 1;
        rst
    }

    fn check_policy_hash(&mut self) -> Result<(), DurangoError> {
        let serialized_rph = colima::serialize_request_policy_hash()?;
        let response = self.send(&serialized_rph)?;
        let parsed_response = colima::parse_mexico_city_response(&response)?;
        match parsed_response.status {
            colima::ResponseStatus::SUCCESS => {
                let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
                if self.policy_hash != received_hash {
                    return Err(DurangoError::MismatchError {
                        variable: "check_pi_hash",
                        expected: self.policy.pi_hash().clone().into_bytes(),
                        received: received_hash.as_bytes().to_vec(),
                    });
                } else {
                    return Ok(());
                }
            }
            _ => {
                return Err(DurangoError::ResponseError(
                    "check_policy_hash",
                    parsed_response.status,
                ));
            }
        }
    }

    fn check_pi_hash(&mut self) -> Result<(), DurangoError> {
        let serialized_request = colima::serialize_request_pi_hash()?;
        let mut iterations = 0;
        let max_iterations = 10;
        while iterations < max_iterations {
            let response = self.send(&serialized_request)?;
            let parsed_response = colima::parse_mexico_city_response(&response)?;
            let status = parsed_response.get_status();
            match status {
                colima::ResponseStatus::SUCCESS => {
                    let received_hash = hex::encode(&parsed_response.get_pi_hash().data);
                    if received_hash == *self.policy.pi_hash() {
                        return Ok(());
                    } else {
                        return Err(DurangoError::MismatchError {
                            variable: "check_pi_hash",
                            expected: self.policy.pi_hash().clone().into_bytes(),
                            received: received_hash.into_bytes(),
                        });
                    }
                }
                colima::ResponseStatus::FAILED_NOT_READY => {
                    std::thread::sleep(std::time::Duration::from_millis(5000));
                    // go for another iteration
                }
                _ => {
                    return Err(DurangoError::ResponseError("check_pi_hash", status));
                }
            }
            iterations = iterations + 1;
        }
        return Err(DurangoError::ExcessiveIterationError("check_pi_hash"));
    }

    /// send the data to the mexico_city path on the sinaloa server.
    // TODO: This function has return points scattered all over, making it very hard to follow
    fn send(&mut self, data: &Vec<u8>) -> Result<Vec<u8>, DurangoError> {
        let mut enclave_session_id: u32 = 0;
        match self.remote_session_id {
            Some(session_id) => enclave_session_id = session_id,
            None => (),
        }

        self.tls_session.write_all(&data[..])?;

        let mut outgoing_data_vec = Vec::new();
        let outgoing_data = Vec::new();
        let outgoing_data_option = self.process(outgoing_data)?; // intentionally sending no data to process
        match outgoing_data_option {
            Some(outgoing_data) => outgoing_data_vec.push(outgoing_data),
            None => (),
        }

        let mut incoming_data_vec: Vec<Vec<u8>> = Vec::new();

        loop {
            for outgoing_data in &outgoing_data_vec {
                let incoming_data_option =
                    self.post_mexico_city(enclave_session_id, &outgoing_data)?;
                match incoming_data_option {
                    Some((received_session_id, received_data_vec)) => {
                        enclave_session_id = received_session_id;
                        for received_data in received_data_vec {
                            incoming_data_vec.push(received_data);
                        }
                    }
                    None => (),
                }
            }

            outgoing_data_vec.clear();
            if incoming_data_vec.len() > 0 {
                for incoming_data in &incoming_data_vec {
                    let outgoing_data_option = self.process(incoming_data.to_vec())?;
                    match outgoing_data_option {
                        Some(outgoing_data) => {
                            outgoing_data_vec.push(outgoing_data);
                        }
                        None => (),
                    }
                }
                incoming_data_vec.clear();
            } else {
                // try process with no data to see if it wants to send
                let empty_vec = Vec::new();
                let outgoing_data_option = self.process(empty_vec)?;
                match outgoing_data_option {
                    Some(outgoing_data) => outgoing_data_vec.push(outgoing_data),
                    None => (),
                }
            }

            let plaintext_data_option = self.get_data()?;
            match plaintext_data_option {
                Some(plaintext_data) => {
                    self.remote_session_id = Some(enclave_session_id);
                    return Ok(plaintext_data);
                }
                None => (),
            }
        }
    }

    fn process(&mut self, input: Vec<u8>) -> Result<Option<Vec<u8>>, DurangoError> {
        let mut ret_option = None;
        let mut output: std::vec::Vec<u8> = std::vec::Vec::new();
        if input.len() > 0 && (!self.tls_session.is_handshaking() || self.tls_session.wants_read())
        {
            let mut slice = &input[..];
            self.tls_session.read_tls(&mut slice)?;

            self.tls_session.process_new_packets()?;
        }
        if self.tls_session.wants_write() {
            self.tls_session.write_tls(&mut output)?;
            ret_option = Some(output);
        }
        Ok(ret_option)
    }

    fn get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, DurangoError> {
        let mut ret_val = None;
        let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        self.tls_session.process_new_packets()?;
        let read_received = self.tls_session.read_to_end(&mut received_buffer);
        if read_received.is_ok() && received_buffer.len() > 0 {
            ret_val = Some(received_buffer)
        }
        Ok(ret_val)
    }

    fn post_mexico_city(
        &self,
        enclave_session_id: u32,
        data: &Vec<u8>,
    ) -> Result<Option<(u32, Vec<Vec<u8>>)>, DurangoError> {
        println!("post_mexico_city started");
        let string_data = base64::encode(data);
        let combined_string = format!("{:} {:}", enclave_session_id, string_data);

        let dest_url = format!("http://{:}/mexico_city", self.policy.sinaloa_url());
        let client_build = reqwest::ClientBuilder::new().timeout(None).build()?;
        let mut ret = client_build
            .post(dest_url.as_str())
            .body(combined_string)
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            return Err(DurangoError::InvalidReqwestError(ret.status()));
        }
        let body = ret.text()?;

        let body_items = body.split_whitespace().collect::<Vec<&str>>();
        if body_items.len() > 0 {
            let received_session_id = body_items[0].parse::<u32>()?;
            let mut return_vec = Vec::new();
            for x in 1..body_items.len() {
                let this_body_data = base64::decode(&body_items[x])?;
                return_vec.push(this_body_data);
            }
            if return_vec.len() > 0 {
                Ok(Some((received_session_id, return_vec)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    // APIs for testing: expose internal functions
    #[cfg(test)]
    pub fn pub_read_all_bytes_in_file<P>(filename: P) -> Result<Vec<u8>, DurangoError>
    where
        P: AsRef<path::Path>
    {
        Durango::read_all_bytes_in_file(filename)
    }

    #[cfg(test)]
    pub fn pub_read_cert<P>(filename: P) -> Result<rustls::Certificate, DurangoError>
    where
        P: AsRef<path::Path>
    {
        Durango::read_cert(filename)
    }

    #[cfg(test)]
    pub fn pub_read_private_key<P>(filename: P) -> Result<rustls::PrivateKey, DurangoError>
    where
        P: AsRef<path::Path>
    {
        Durango::read_private_key(filename)
    }

    #[cfg(test)]
    pub fn pub_init_self_signed_cert_client_config(
        client_cert: rustls::Certificate,
        client_priv_key: rustls::PrivateKey,
        enclave_cert_hash: Vec<u8>,
        enclave_name: &str,
        ciphersuite_string: &str,
    ) -> Result<rustls::ClientConfig, DurangoError> {
        Durango::init_self_signed_cert_client_config(
            client_cert,
            client_priv_key,
            enclave_cert_hash,
            enclave_name,
            ciphersuite_string,
        )
    }

    #[cfg(test)]
    pub fn pub_send(&mut self, data: &Vec<u8>) -> Result<Vec<u8>, DurangoError> {
        self.send(data)
    }

    #[cfg(test)]
    pub fn pub_process(&mut self, input: Vec<u8>) -> Result<Option<Vec<u8>>, DurangoError> {
        self.process(input)
    }

    #[cfg(test)]
    pub fn pub_get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, DurangoError> {
        self.get_data()
    }
}

#[allow(dead_code)]
fn print_hex(data: &Vec<u8>) -> String {
    let mut ret_val = String::new();
    for this_byte in data {
        ret_val.push_str(format!("{:02x}", this_byte).as_str());
    }
    ret_val
}

#[allow(dead_code)]
fn decode_tls_message(data: &Vec<u8>) {
    match data[0] {
        0x16 => {
            print!("Handshake: ");
            match data[5] {
                0x01 => println!("Client hello"),
                0x02 => println!("Server hello"),
                0x0b => println!("Certificate"),
                0x0c => println!("ServerKeyExchange"),
                0x0d => println!("CertificateRequest"),
                0x0e => println!("ServerHelloDone"),
                0x10 => println!("ClientKeyExchange"),
                0x0f => println!("CertificateVerify"),
                0x14 => println!("Finished"),
                _ => println!("Unknown"),
            }
        }
        0x14 => {
            println!("ChangeCipherSpec");
        }
        0x15 => {
            println!("Alert");
        }
        0x17 => {
            println!("ApplicationData");
        }
        _ => println!("Unknown"),
    }
}
