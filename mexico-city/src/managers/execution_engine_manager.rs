//! Execution engine management code, decoding protocol messages and turning them into
//! actions on the Veracruz host provisioning state.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::{
    MexicoCityError, ProtocolState, ProvisioningResponse,
    ProvisioningResult,
};
use execution_engine::hcall::common::{LifecycleState};
use colima::colima::{
    MexicoCityRequest as REQUEST, MexicoCityRequest_oneof_message_oneof as MESSAGE,
};
use lazy_static::lazy_static;
#[cfg(any(feature = "tz", feature = "nitro"))]

use std::sync::Mutex;
#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;
use std::{collections::HashMap, result::Result, vec::Vec};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzRole};

////////////////////////////////////////////////////////////////////////////////
// The buffer of incoming data.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    //TODO, wrap into a chihuahua management object.
    static ref INCOMING_BUFFER_HASH: Mutex<HashMap<u32, Vec<u8>>> = Mutex::new(HashMap::new());
}

////////////////////////////////////////////////////////////////////////////////
// Utility functions.
////////////////////////////////////////////////////////////////////////////////

///// Checks that the host provisioning state is in one of a number of expected
///// states, otherwise raises an error with an error message detailing the
///// mismatch.
//#[inline]
//fn check_state(current: &LifecycleState, expected: &[LifecycleState]) -> bool {
    //expected.contains(&current)
//}

////////////////////////////////////////////////////////////////////////////////
// Protocol response messages.
////////////////////////////////////////////////////////////////////////////////

//TODO: wrap inside protocol_state
/// Encodes a successful computation result, ready for transmission back to whoever requested a
/// result.
#[inline]
fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
    colima::serialize_result(colima::ResponseStatus::SUCCESS as i32, result)
        .unwrap_or_else(|err| panic!(err))
}

/// Encodes an error code that the virtual machine program produced, ready for
/// transmission back to swhoever requested a result.
fn response_error_code_returned(error_code: &i32) -> std::vec::Vec<u8> {
    colima::serialize_result(
        colima::ResponseStatus::FAILED_ERROR_CODE_RETURNED as i32,
        Some(error_code.to_le_bytes().to_vec()),
    )
    .unwrap_or_else(|err| panic!(err))
}

/// Encodes an error code indicating that the enclace is not ready to receive a
/// particular type of message.
fn response_not_ready() -> super::ProvisioningResult {
    assert!(false);
    let rst = colima::serialize_result(colima::ResponseStatus::FAILED_NOT_READY as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

/// Encodes an error code indicating that a principal with an invalid role tried
/// to perform an action.
fn response_invalid_role() -> super::ProvisioningResult {
    assert!(false);
    let rst = colima::serialize_result(colima::ResponseStatus::FAILED_INVALID_ROLE as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

/// Encodes an error code indicating that somebody sent an invalid or malformed
/// protocol request.
fn response_invalid_request() -> super::ProvisioningResult {
    assert!(false);
    let rst =
        colima::serialize_result(colima::ResponseStatus::FAILED_INVALID_REQUEST as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

////////////////////////////////////////////////////////////////////////////////
// Protocol message dispatch.
////////////////////////////////////////////////////////////////////////////////

/// Returns the SHA-256 digest of the provisioned program.  Fails if no hash has
/// yet been computed.
fn dispatch_on_pi_hash(_ : colima::RequestPiHash, protocol_state: &ProtocolState) -> ProvisioningResult {
    let response = colima::serialize_pi_hash(b"deprecated")?;
    Ok(ProvisioningResponse::Success { response })
}

/// Returns the SHA-256 digest of the policy.
fn dispatch_on_policy_hash(protocol_state: &ProtocolState) -> ProvisioningResult {
    let hash = protocol_state.get_policy_hash();
    let response = colima::serialize_policy_hash(hash.as_bytes())?;
    Ok(ProvisioningResponse::Success { response })
}

/// Returns the current lifecycle state of the host provisioning state.  This
/// state can be queried unconditionally (though it may change between the query
/// being serviced and being received back/being acted upon...)
fn dispatch_on_request_state(_ : &ProtocolState) -> ProvisioningResult {
    //TODO REMOVE???
    let response =
        colima::serialize_machine_state(u8::from(0))?;
    Ok(ProvisioningResponse::Success { response })
}

/// Returns the result of a computation, computing the result first.  Fails if
/// we are not in the `LifecycleState::ReadyToExecute` state.
fn dispatch_on_result(colima::RequestResult{ file_name, .. } : colima::RequestResult, protocol_state: &mut ProtocolState, client_id: u64,) -> ProvisioningResult {
    if !protocol_state.is_modified() {
        let result = protocol_state.read_file(&VeracruzCapabilityIndex::Principal(client_id),"output")?;
        let response = response_success(result);
        return Ok(ProvisioningResponse::Success { response });
    }
    protocol_state.launch(&file_name,client_id)
}

/// Processes a request from a client to perform a platform shutdown.  Returns
/// `true` iff we have reached a threshold wherein everybody who needs to
/// request a shutdown can go ahead and do so.
#[inline]
fn dispatch_on_shutdown(
    protocol_state: &mut ProtocolState,
    client_id: u64,
) -> Result<(bool, ProvisioningResult), MexicoCityError> {
    Ok((
        protocol_state.request_and_check_shutdown(client_id)?,
        Ok(ProvisioningResponse::Success {
            response: response_success(None),
        }),
    ))
}

/// Provisions a program into the host provisioning state.  Fails if we are not
/// in `LifecycleState::Initial` or if the provisioned program is malformed in
/// some way.
///
/// Note: this doesn't invalidate the host state if something is wrong with the
/// program, as the program provider can try again by uploading another program,
/// which seems benign.  Should this change?
fn dispatch_on_program(
    protocol_state: &mut ProtocolState,
    colima::Program { file_name, code, .. }: colima::Program,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.write_file(&VeracruzCapabilityIndex::Principal(client_id),&file_name,&code)?; 
    let response = colima::serialize_result(colima::ResponseStatus::SUCCESS as i32, None)?;
    Ok(ProvisioningResponse::Success { response })
}

/// Provisions a data source into the host provisioning state.  Fails if we are
/// not in `LifecycleState::DataSourcesLoading`.  If we are still expecting more
/// data then we stay in state `LifecycleState::DataSourcesLoading`, otherwise
/// if this represents the last data provisioning step then the host
/// provisioning state automatically switches to
/// `LifecycleState::ReadyToExecute` or `LifecycleState::StreamSourcesLoading`
/// if stream data is required.
fn dispatch_on_data(
    protocol_state: &mut ProtocolState,
    colima::Data {
        data, file_name, ..
    }: colima::Data,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.write_file(&VeracruzCapabilityIndex::Principal(client_id),file_name.as_str(),data.as_slice())?; 
    let response = colima::serialize_result(colima::ResponseStatus::SUCCESS as i32, None)?;
    Ok(ProvisioningResponse::Success { response })
}

/// Provisions a stream source into the host provisioning state.  Fails if we are
/// not in `LifecycleState::StreamSourcesLoading`.  If we are still expecting more
/// data then we stay in state `LifecycleState::StreamSourcesLoading`, otherwise
/// if this represents the last data provisioning step then the host
/// provisioning state automatically switches to
/// `LifecycleState::ReadyToExecute`.
fn dispatch_on_stream(
    protocol_state: &mut ProtocolState,
    colima::Data {
        data, file_name, ..
    }: colima::Data,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.write_file(&VeracruzCapabilityIndex::Principal(client_id),file_name.as_str(),data.as_slice())?;
    let response = colima::serialize_result(colima::ResponseStatus::SUCCESS as i32, None)?;
    Ok(ProvisioningResponse::Success { response })
}

/// Signals the next round of computation. It will reload the program and all (static) data,
/// and load the current result as the `previous_result` for the next round.
/// Fails if the enclave is not in `LifecycleState::FinishedExecuting`.
fn dispatch_on_next_round(
    protocol_state: &mut ProtocolState,
) -> ProvisioningResult {
    protocol_state.reload()?;
    Ok(ProvisioningResponse::Success {
        response: response_success(None),
    })
}

/// Branches on a decoded protobuf message, `request`, and invokes appropriate
/// behaviour from more specialised functions.
///
/// TODO: Do we want any one of the client roles to be able to terminate the
/// operation? There's no guarantee of a timely shutdown, so it doesn't really
/// guarantee better security, but if a client detects something's wrong, they
/// may want the ability.
fn dispatch_on_request(
    client_id: u64,
    roles: &Vec<VeracruzRole>,
    request: MESSAGE,
) -> ProvisioningResult {
    let mut protocol_state_guard = super::PROTOCOL_STATE.lock()?;
    let protocol_state = protocol_state_guard
        .as_mut()
        .ok_or_else(|| MexicoCityError::UninitializedProtocolState)?;

    match request {
        MESSAGE::data(data) => {
            dispatch_on_data(protocol_state, data, client_id)
        }
        MESSAGE::program(prog) => {
            dispatch_on_program(protocol_state, prog, client_id)
        }
        MESSAGE::request_pi_hash(pi_hash_request) => dispatch_on_pi_hash(pi_hash_request, protocol_state),
        MESSAGE::request_policy_hash(_) => dispatch_on_policy_hash(protocol_state),
        MESSAGE::request_result(result_request) => {
            dispatch_on_result(result_request,protocol_state,client_id)
        }
        MESSAGE::request_state(_) => dispatch_on_request_state(protocol_state),
        MESSAGE::request_shutdown(_) => {
            let (is_dead, response) = dispatch_on_shutdown(protocol_state, client_id.into())?;

            if is_dead {
                *protocol_state_guard = None;
            }

            response
        }
        MESSAGE::stream(stream) => {
            dispatch_on_stream(protocol_state, stream, client_id)
        }
        MESSAGE::request_next_round(_) => {
            dispatch_on_next_round(protocol_state)
        }
        _otherwise => response_invalid_request(),
    }
}

/// Tries to parse the incoming data into a `MexicoCityRequest`.  If this is not
/// possible, returns `Err(reason)`.  If we still need to receive more data in
/// order to parse a full request, returns `Ok(None)`.  Otherwise, returns
/// `Ok(request)` for the parsed request.
///
/// TODO: harden this against potential malfeasance.  See the note, below.
fn parse_incoming_buffer(
    tls_session_id: u32,
    mut input: Vec<u8>,
) -> Result<Option<colima::MexicoCityRequest>, MexicoCityError> {
    let mut incoming_buffer_hash = INCOMING_BUFFER_HASH.lock()?;

    // First, make sure there is an entry in the hash for the TLS session.
    if incoming_buffer_hash.get(&tls_session_id).is_none() {
        incoming_buffer_hash.insert(tls_session_id, Vec::new());
    }

    // This should not panic, given the above.  If it does, something is wrong.
    let incoming_buffer = incoming_buffer_hash.get_mut(&tls_session_id).ok_or(
        MexicoCityError::UnavailableIncomeBufferError(tls_session_id as u64),
    )?;

    incoming_buffer.append(&mut input);

    // NB: `parse_from_bytes()` returning failure is interpreted as meaning the
    // full protocol buffer has not yet been received. So we return `Ok(None)`
    // with the hope that eventually we will receive all of it, and then
    // `parse_from_bytes()` will return `Ok(parsed)`. In a well-behaving system,
    // this is reasonable.  In a poorly-behaved system (under attack, clients
    // just getting confused) it is not reasonable, and can eventually result in
    // "Out of Memory" or Garbage out.
    //
    // TODO: It would be nice to check the error, and then determine if this might
    // be the case or if it is hopeless and we could just error out.
    match protobuf::parse_from_bytes::<colima::MexicoCityRequest>(&incoming_buffer) {
        Err(_) => Ok(None),
        Ok(parsed) => {
            incoming_buffer_hash.remove(&tls_session_id);
            Ok(Some(parsed))
        }
    }
}

/// Top-level function which tries to parse an incoming buffer of bytes, `input`,
/// into a protobuf protocol message.  If we cannot yet parse the buffer, then
/// we return a protocol message indicating that we are waiting for more data,
/// otherwise we branch on the message contained inside the parsed protobuf
/// request frame: if it is valid then dispatch on that decoded message,
/// otherwise fail with an invalid request message.
pub fn dispatch_on_incoming_data(
    tls_session_id: u32,
    client_id: u64,
    roles: &Vec<VeracruzRole>,
    input: &Vec<u8>,
) -> ProvisioningResult {
    match parse_incoming_buffer(tls_session_id, input.clone())? {
        None => Ok(ProvisioningResponse::WaitForMoreData),
        Some(REQUEST {
            message_oneof: None,
            ..
        }) => response_invalid_request(),
        Some(REQUEST {
            message_oneof: Some(request),
            ..
        }) => dispatch_on_request(client_id, roles, request),
    }
}
