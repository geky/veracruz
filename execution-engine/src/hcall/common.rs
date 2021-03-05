//! Common code for implementing Veracruz host-calls
//!
//! ## About
//!
//! The Veracruz H-call interface consists of the following functions:
//! - `__veracruz_hcall_input_count()` which returns the count of secret
//!   data sources available to the program,
//! - `__veracruz_hcall_read_input()` which fills a WASM buffer with a
//!   particular input,
//! - `__veracruz_hcall_input_size()` which returns the size, in bytes, of a
//!   particular input,
//! - `__veracruz_hcall_write_output()` which can be used by the WASM
//!   program to register its result by pointing the host to a WASM buffer
//!   which is then copied into the host,
//! - `__veracruz_hcall_getrandom()` which fills a WASM buffer with random
//!   bytes taken from a platform-specific entropy source.
//!
//! The implementation of some of these functions relies on execution-engine
//! specific details, so they are mostly implemented in the engine-specific
//! files in this directory.  This file contains material common to all
//! implementations.
//!
//! Also defined in this file is the Veracruz state machine state.  The Veracruz
//! host progresses through a particular series of states during provisioning
//! to ensure that Veracruz is secure, and also that it acts a little like a
//! function which can be partially-applied.
//!
//! Finally, the Veracruz host state is also defined in this file.  This keeps
//! track of the state of the host as material is provisioned into the Veracruz
//! enclave, and is used by the host to implement some (actually, most) of the
//! H-calls mentioned above.  In particular, the host state keeps track of:
//! - The number of expected data sources that the host is expecting,
//!   derived from the policy,
//! - The number of expected data sources already provisioned, and various
//!   bits of metadata about them (e.g. who provisioned them),
//! - The current machine state, e.g. `MachineState::ReadyToExecute`,
//! - Any result that the WASM program executing on Veracruz may have
//!   written to the host with the `__veracruz_hcall_write_output()` H-call.
//!   Note that this is stored as an uninterpreted set of bytes in the host,
//!   the host doesn't necessarily know how to interpret it: that's a detail
//!   to be agreed between the participants in the computation,
//! - Some WASM engine specific details, including a reference to the WASM
//!   module executing and the linear memory of the module.  As these types
//!   are engine-specific, we abstract over them with type-variables here.
//!
//! We also include a lot of generic material for working with the host state,
//! including functions for changing various values, and bumping the host state
//! around the state machine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use crate::error::common::VeracruzError;
use err_derive::Error;
use serde::{Deserialize, Serialize};
use std::{
    string::{String, ToString},
    vec::Vec,
};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzCapability};
use crate::hcall::buffer::{VFS, VFSError};

#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};

////////////////////////////////////////////////////////////////////////////////
// The H-Call API
////////////////////////////////////////////////////////////////////////////////

/// Name of the `__veracruz_hcall_input_count` H-call.
pub(crate) const HCALL_INPUT_COUNT_NAME: &'static str = "__veracruz_hcall_input_count";
/// Name of the `__veracruz_hcall_input_size` H-call.
pub(crate) const HCALL_INPUT_SIZE_NAME: &'static str = "__veracruz_hcall_input_size";
/// Name of the `__veracruz_hcall_read_input` H-call.
pub(crate) const HCALL_READ_INPUT_NAME: &'static str = "__veracruz_hcall_read_input";
/// Name of the `__veracruz_hcall_write_output` H-call.
pub(crate) const HCALL_WRITE_OUTPUT_NAME: &'static str = "__veracruz_hcall_write_output";
/// Name of the `__veracruz_hcall_getrandom` H-call.
pub(crate) const HCALL_GETRANDOM_NAME: &'static str = "__veracruz_hcall_getrandom";
/// Name of the `__veracruz_hcall_read_previous_result` H-call.
pub(crate) const HCALL_READ_PREVIOUS_RESULT_NAME: &str = "__veracruz_hcall_read_previous_result";
/// Name of the `__veracruz_hcall_previous_result_size` H-call.
pub(crate) const HCALL_PREVIOUS_RESULT_SIZE_NAME: &str = "__veracruz_hcall_previous_result_size";
/// Name of the `__veracruz_hcall_has_previous_result` H-call.
pub(crate) const HCALL_HAS_PREVIOUS_RESULT_NAME: &str = "__veracruz_hcall_has_previous_result";
/// H-call code for the `__veracruz_hcall_stream_count` H-call.
pub(crate) const HCALL_STREAM_COUNT_NAME: &str = "__veracruz_hcall_stream_count";
/// H-call code for the `__veracruz_hcall_stream_size` H-call.
pub(crate) const HCALL_STREAM_SIZE_NAME: &str = "__veracruz_hcall_stream_size";
/// H-call code for the `__veracruz_hcall_read_stream` H-call.
pub(crate) const HCALL_READ_STREAM_NAME: &str = "__veracruz_hcall_read_stream";

////////////////////////////////////////////////////////////////////////////////
// Provisioning errors
////////////////////////////////////////////////////////////////////////////////

//TODO: REMOVE THIS ERROR
/// Errors that can occur during host provisioning.  These are errors that may
/// be reported back to principals in the Veracruz computation over the Veracruz
/// wire protocols, for example if somebody tries to provision data when that is
/// not expected, or similar.  Some may be recoverable errors, some may be fatal
/// errors due to programming bugs.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum HostProvisioningError {
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "HostProvisioningError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    /// No linear memory/heap could be identified in the WASM module.
    #[error(
        display = "HostProvisioningError: No linear memory could be found in the supplied WASM module."
    )]
    NoLinearMemoryFound,
    #[error(display = "HostProvisioningError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// The program module could not be properly instantiated by the WASM engine
    /// for some reason.
    #[error(display = "HostProvisioningError: Failed to instantiate the WASM module.")]
    ModuleInstantiationFailure,
    /// A lock could not be obtained for some reason.
    #[error(display = "HostProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    #[error(display = "HostProvisioningError: Wasmi Error: {}.", _0)]
    WasmiError(String),
    /// The host provisioning state has not been initialized.  This should never
    /// happen and is a bug.
    #[error(
        display = "HostProvisioningError: Uninitialized host provisioning state (this is a potential bug)."
    )]
    HostProvisioningStateNotInitialized,
    /// The data or stream data cannot be sorted. This should never happen and is a bug.
    #[error(
        display = "HostProvisioningError: Failed to sort the incoming data or incoming stream (this is a potential bug)."
    )]
    CannotSortDataOrStream,
    #[error(
        display = "HostProvisioningError: VFS Error {}.", _0
    )]
    VFSError(#[error(source)]VFSError),
    //TODO: potential remove this 
    #[error(
        display = "HostProvisioningError: File {} cannot be found.", _0
    )]
    FileNotFound(String),
}

//TODO: move to a separate fill error.rs
// Convertion from any error raised by any mutex of type <T> to HostProvisioningError.
impl<T> From<std::sync::PoisonError<T>> for HostProvisioningError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        HostProvisioningError::FailedToObtainLock(format!("{:?}", error))
    }
}

impl From<wasmi::Error> for HostProvisioningError {
    fn from(error: wasmi::Error) -> Self {
        HostProvisioningError::WasmiError(format!("{:?}", error))
    }
}

////////////////////////////////////////////////////////////////////////////////
// The Veracruz provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// The state of the Veracruz machine, which captures metadata as the Veracruz
/// state is gradually "provisioned" by the data and program providers.  Also
/// contains enough data to properly implement the Veracruz H-calls.
#[derive(Clone)]
// TODO: remove MOST, except:
// - memory
// - program_module ? possibly can do on-demand allocation
// in the favour of FS.
pub struct VFSService {
    vfs : Arc<Mutex<VFS>>,
}

impl VFSService {
    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying host states.
    ////////////////////////////////////////////////////////////////////////////
    
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        vfs : Arc<Mutex<VFS>>,
    ) -> Self {
        Self { vfs }
    }

    /// Append to a file.
    pub(crate) fn write_file_base(&mut self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Write)?;
        self.vfs.lock()?.write(file_name,data)?;
        Ok(())
    }

    /// Append to a file.
    pub(crate) fn append_file_base(&mut self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Write)?;
        self.vfs.lock()?.append(file_name,data)?;
        Ok(())
    }

    /// Read from a file
    pub(crate) fn read_file_base(&self, client_id: &VeracruzCapabilityIndex, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Read)?;
        Ok(self.vfs.lock()?.read(file_name)?)
    }
    
    /// Read from a file
    pub(crate) fn count_file_base(&self, prefix: &str) -> Result<u64, HostProvisioningError> {
        Ok(self.vfs.lock()?.count(prefix)?)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal host errors
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz host immediately.  This
/// is akin to a "kernel panic" for Veracruz: these errors are not passed to the
/// WASM program running on the platform, but are instead fundamental issues
/// that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalHostError {
    /// The Veracruz host was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "FatalVeracruzHostError: Bad arguments passed to host function '{}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        //NOTE: use `String` instead of `&'static str` to make serde happy.
        /// The name of the host function that was being invoked.
        function_name: String,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz host.
    #[error(
        display = "FatalVeracruzHostError: Unknown H-call invoked: '{}'.",
        index
    )]
    UnknownHostFunction {
        /// The host call index of the unknown function that was invoked.
        index: usize,
    },
    /// The host failed to read a range of bytes, starting at a base address,
    /// from the running WASM program's linear memory.
    #[error(
        display = "FatalVeracruzHostError: Failed to read {} byte(s) from WASM memory at address {}.",
        bytes_to_be_read,
        memory_address
    )]
    MemoryReadFailed {
        /// The base memory address that was being read.
        memory_address: usize,
        /// The number of bytes that were being read.
        bytes_to_be_read: usize,
    },
    /// The host failed to write a range of bytes, starting from a base address,
    /// to the running WASM program's linear memory.
    #[error(
        display = "FatalVeracruzHostError: Failed to write {} byte(s) to WASM memory at address {}.",
        bytes_to_be_written,
        memory_address
    )]
    MemoryWriteFailed {
        /// The base memory address that was being written.
        memory_address: usize,
        /// The number of bytes that were being written.
        bytes_to_be_written: usize,
    },
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalVeracruzHostError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalVeracruzHostError: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(
        display = "FatalVeracruzHostError: Failed to find the entry point in the WASM program."
    )]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalVeracruzHostError: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "FatalVeracruzHostError: WASM program returns code other than i32.")]
    ReturnedCodeError,
    /// Wrapper for WASI Trap.
    #[error(display = "FatalVeracruzHostError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalVeracruzHostError: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    #[error(display = "FatalVeracruzHostError: Program {} cannot be found.", file_name)]
    ProgramCannotFound{
        file_name : String,
    },
    /// Wrapper for Virtual FS Error.
    #[error(display = "FatalVeracruzHostError: VFS Error: {:?}.", _0)]
    VFSError(#[error(source)] VFSError),
    /// Wrapper for direct error message.
    #[error(display = "FatalVeracruzHostError: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    //TODO REMOVE
    #[error(display = "FatalVeracruzHostError: provisioning error {:?}.", _0)]
    ProvisionError(#[error(source)] HostProvisioningError),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "FatalVeracruzHostError: Unknown error.")]
    Generic,
}

impl From<String> for FatalHostError {
    fn from(err: String) -> Self {
        FatalHostError::DirectErrorMessage(err)
    }
}

impl From<&str> for FatalHostError {
    fn from(err: &str) -> Self {
        FatalHostError::DirectErrorMessage(err.to_string())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

/// The return type for H-Call implementations.
///
/// From *the viewpoint of the host* a H-call can either fail spectacularly
/// with a runtime trap, in which case `Err(err)` is returned, with `err`
/// detailing what went wrong, and the Veracruz host thereafter terminating
/// or otherwise entering an error state, or succeeds with `Ok(())`.
///
/// From *the viewpoint of the WASM program* a H-call can either fail
/// spectacularly, as above, in which case WASM program execution is aborted
/// with the WASM program itself not being able to do anything about this,
/// succeeds with the desired effect and a success error code returned, or
/// fails with a recoverable error in which case the error code details what
/// went wrong and what can be done to fix it.
pub(crate) type HCallError = Result<VeracruzError, FatalHostError>;

/// Details the arguments expected by the module's entry point, if any is found.
pub(crate) enum EntrySignature {
    /// The expected entry point (e.g. "main") is not found in the WASM module
    /// or it was found and it did not have a recognisable type signature.
    NoEntryFound,
    /// The entry point does not expect any parameters.
    NoParameters,
    /// The entry point expects a dummy `argv` and an `argc` to be supplied.
    ArgvAndArgc,
}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `mexico-city` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that a factory method, in the file `hcall/factory.rs` will return an
/// opaque instance of this trait depending on the
pub trait ExecutionEngine: Send {
    /// Invokes the entry point of the WASM program `file_name`.  Will fail if
    /// the WASM program fails at runtime.  On success, returns the succ/error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<i32, FatalHostError>;
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////////
