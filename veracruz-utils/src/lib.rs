//! The Veracruz utility library
//!
//! Material that doesn't fit anywhere else, or is common across many modules.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

pub mod policy;
pub use crate::policy::*;

#[cfg(feature = "tz")]
pub mod runtime_manager_opcode;
#[cfg(feature = "tz")]
pub use crate::runtime_manager_opcode::*;

#[cfg(feature = "tz")]
pub mod trustzone_root_enclave_opcode;
#[cfg(feature = "tz")]
pub use crate::trustzone_root_enclave_opcode::*;

#[cfg(any(feature = "nitro", feature = "linux"))]
pub mod nitro;
#[cfg(any(feature = "nitro", feature = "linux"))]
pub use crate::nitro::*;

#[cfg(any(feature = "nitro", feature = "linux"))]
pub mod vsocket;
#[cfg(any(feature = "nitro", feature = "linux"))]
pub use self::vsocket::*;
#[cfg(any(feature = "nitro"))]
pub mod nitro_enclave;
#[cfg(any(feature = "nitro"))]
pub use self::nitro_enclave::*;
