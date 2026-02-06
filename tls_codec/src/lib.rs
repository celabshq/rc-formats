#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    rust_2018_idioms,
    unused_lifetimes
)]

//! ## Usage
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use tls_codec::{TlsVecU8, Serialize, Deserialize};
//! let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];
//!
//! let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
//! assert_eq!(1, a);
//! println!("b: {:?}", b);
//! let v = TlsVecU8::<u8>::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
//! assert_eq!(&[77, 88, 1, 99], v.as_slice());
//! # }
//! ```

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::String, vec::Vec};
use core::fmt::{self, Display};
#[cfg(feature = "std")]
use std::io::{Read, Write};

mod arrays;
mod primitives;
mod quic_vec;
mod tls_vec;
mod varint;

pub use tls_vec::{
    SecretTlsVecU8, SecretTlsVecU16, SecretTlsVecU24, SecretTlsVecU32, TlsByteSliceU8,
    TlsByteSliceU16, TlsByteSliceU24, TlsByteSliceU32, TlsByteVecU8, TlsByteVecU16, TlsByteVecU24,
    TlsByteVecU32, TlsSliceU8, TlsSliceU16, TlsSliceU24, TlsSliceU32, TlsVecU8, TlsVecU16,
    TlsVecU24, TlsVecU32,
};

#[cfg(feature = "std")]
pub use quic_vec::{SecretVLBytes, rw as vlen};
pub use quic_vec::{VLByteSlice, VLBytes};

#[cfg(feature = "derive")]
pub use tls_codec_derive::{
    TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize,
};

#[cfg(feature = "conditional_deserialization")]
pub use tls_codec_derive::conditionally_deserializable;

pub use varint::TlsVarInt;

/// Errors that are thrown by this crate.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Error {
    /// An error occurred during encoding.
    EncodingError(String),

    /// The length of a vector is invalid.
    InvalidVectorLength,

    /// Error writing everything out.
    InvalidWriteLength(String),

    /// Invalid input when trying to decode a primitive integer.
    InvalidInput,

    /// An error occurred during decoding.
    DecodingError(String),

    /// Reached the end of a byte stream.
    EndOfStream,

    /// Found unexpected data after deserializing.
    TrailingData,

    /// An unknown value in an enum.
    /// The application might not want to treat this as an error because it is
    /// only an unknown value, not an invalid value.
    UnknownValue(u64),

    /// An internal library error that indicates a bug.
    LibraryError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::EndOfStream,
            _ => Self::DecodingError(format!("io error: {e:?}")),
        }
    }
}

/// The `Size` trait needs to be implemented by any struct that should be
/// efficiently serialized.
/// This allows to collect the length of a serialized structure before allocating
/// memory.
pub trait Size {
    fn tls_serialized_len(&self) -> usize;
}

/// The `Serialize` trait provides functions to serialize a struct or enum.
///
/// The trait provides two functions:
/// * `tls_serialize` that takes a buffer to write the serialization to
/// * `tls_serialize_detached` that returns a byte vector
pub trait Serialize: Size {
    /// Serialize `self` and write it to the `writer`.
    /// The function returns the number of bytes written to `writer`.
    #[cfg(feature = "std")]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error>;

    /// Serialize `self` and return it as a byte vector.
    #[cfg(feature = "std")]
    fn tls_serialize_detached(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(self.tls_serialized_len());
        let written = self.tls_serialize(&mut buffer)?;
        debug_assert_eq!(
            written,
            buffer.len(),
            "Expected that {} bytes were written but the output holds {} bytes",
            written,
            buffer.len()
        );
        if written != buffer.len() {
            Err(Error::EncodingError(format!(
                "Expected that {} bytes were written but the output holds {} bytes",
                written,
                buffer.len()
            )))
        } else {
            Ok(buffer)
        }
    }
}

/// The `SerializeBytes` trait provides a function to serialize a struct or enum.
///
/// The trait provides one function:
/// * `tls_serialize` that returns a byte vector
pub trait SerializeBytes: Size {
    /// Serialize `self` and return it as a byte vector.
    fn tls_serialize(&self) -> Result<Vec<u8>, Error>;
}

/// The `Deserialize` trait defines functions to deserialize a byte slice to a
/// struct or enum.
pub trait Deserialize: Size {
    /// This function deserializes the `bytes` from the provided a [`std::io::Read`]
    /// and returns the populated struct.
    ///
    /// In order to get the amount of bytes read, use [`Size::tls_serialized_len`].
    ///
    /// Returns an error if one occurs during deserialization.
    #[cfg(feature = "std")]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized;

    /// This function deserializes the provided `bytes` and returns the populated
    /// struct. All bytes must be consumed.
    ///
    /// Returns an error if not all bytes are read from the input, or if an error
    /// occurs during deserialization.
    #[cfg(feature = "std")]
    fn tls_deserialize_exact(bytes: impl AsRef<[u8]>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut bytes = bytes.as_ref();
        let out = Self::tls_deserialize(&mut bytes)?;

        if !bytes.is_empty() {
            return Err(Error::TrailingData);
        }

        Ok(out)
    }
}

/// The `DeserializeBytes` trait defines functions to deserialize a byte slice
/// to a struct or enum. In contrast to [`Deserialize`], this trait operates
/// directly on byte slices and can return any remaining bytes.
pub trait DeserializeBytes: Size {
    /// This function deserializes the `bytes` from the provided a `&[u8]`
    /// and returns the populated struct, as well as the remaining slice.
    ///
    /// In order to get the amount of bytes read, use [`Size::tls_serialized_len`].
    ///
    /// Returns an error if one occurs during deserialization.
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;

    /// This function deserializes the provided `bytes` and returns the populated
    /// struct. All bytes must be consumed.
    ///
    /// Returns an error if not all bytes are read from the input, or if an error
    /// occurs during deserialization.
    fn tls_deserialize_exact_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (out, remainder) = Self::tls_deserialize_bytes(bytes)?;

        if !remainder.is_empty() {
            return Err(Error::TrailingData);
        }

        Ok(out)
    }
}

/// A 3 byte wide unsigned integer type as defined in [RFC 5246].
///
/// [RFC 5246]: https://datatracker.ietf.org/doc/html/rfc5246#section-4.4
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct U24([u8; 3]);

impl U24 {
    pub const MAX: Self = Self([255u8; 3]);
    pub const MIN: Self = Self([0u8; 3]);

    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        U24(bytes)
    }

    pub fn to_be_bytes(self) -> [u8; 3] {
        self.0
    }
}

impl From<U24> for usize {
    fn from(value: U24) -> usize {
        const LEN: usize = core::mem::size_of::<usize>();
        let mut usize_bytes = [0u8; LEN];
        usize_bytes[LEN - 3..].copy_from_slice(&value.0);
        usize::from_be_bytes(usize_bytes)
    }
}

impl TryFrom<usize> for U24 {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        const LEN: usize = core::mem::size_of::<usize>();
        // In practice, our usages of this conversion should never be invalid, as the values
        // have to come from `TryFrom<U24> for usize`.
        if value > (1 << 24) - 1 {
            Err(Error::LibraryError)
        } else {
            Ok(U24(value.to_be_bytes()[LEN - 3..].try_into()?))
        }
    }
}

/// A zero copy variant.
pub mod zero_copy {
    use core::marker::PhantomData;

    use super::*;

    // struct {
    //   opaque path_secret<V>;
    // } PathSecret;

    // struct {
    //   opaque joiner_secret<V>;
    //   optional<PathSecret> path_secret;
    //   PreSharedKeyID psks<V>;
    // } GroupSecrets;

    // struct {
    //   KeyPackageRef new_member;
    //   HPKECiphertext encrypted_group_secrets;
    // } EncryptedGroupSecrets;

    // struct {
    //   CipherSuite cipher_suite;
    //   EncryptedGroupSecrets secrets<V>;
    //   opaque encrypted_group_info<V>;
    // } Welcome;

    /// Representing a zero copy type that is parsed into T when needed.
    pub struct RefT<'bytes, T, TRef> {
        bytes: &'bytes [u8],
        _type: PhantomData<(T, TRef)>,
    }

    impl<'bytes, T: DeserializeBytes, TRef: DeserializeRef<'bytes>> RefT<'bytes, T, TRef> {
        /// New ref type
        pub fn new(bytes: &'bytes [u8]) -> Self {
            Self {
                bytes,
                _type: PhantomData,
            }
        }

        /// Build the type.
        ///
        /// Return an owned type `T`.
        pub fn as_type(&self) -> Result<T, Error> {
            T::tls_deserialize_exact_bytes(self.bytes)
        }

        /// Build the type but without copying the bytes.
        ///
        /// This allows getting to the members without copying the bytes.
        pub fn as_type_ref(&self) -> Result<TRef, Error> {
            let (val, remainder) = TRef::tls_deserialize_ref(self.bytes)?;
            debug_assert!(remainder.is_empty());
            if !remainder.is_empty() {
                return Err(Error::TrailingData);
            }

            Ok(val)
        }
    }

    // pub trait Parse {
    //     /// Get the actual value from the input byte slice.
    //     fn get<T>(&self) -> Result<T, Error>;
    // }

    struct HpkeCiphertextTest<'bytes> {
        ciphertext: RefT<'bytes, VLBytes, VLByteSlice<'bytes>>,
        kem_output: RefT<'bytes, VLBytes, VLByteSlice<'bytes>>,
    }

    struct EncryptedGroupSecretsTest<'bytes> {
        new_member: RefT<'bytes, VLBytes, VLByteSlice<'bytes>>,
        encrypted_groupsecrets:
            RefT<'bytes, HpkeCiphertextTest<'bytes>, HpkeCiphertextTest<'bytes>>,
    }

    // Example struct
    struct WelcomeTest<'bytes> {
        suite: RefT<'bytes, u16, u16>, // u16
        secrets: RefT<
            'bytes,
            Vec<EncryptedGroupSecretsTest<'bytes>>,
            Vec<EncryptedGroupSecretsTest<'bytes>>,
        >, // [EncryptedGroupSecrets<'bytes>],
        encrypted_group_info: RefT<'bytes, VLBytes, VLByteSlice<'bytes>>,
    }

    // impl<'bytes> EncryptedGroupSecrets<'bytes> {
    //     fn new_member(&self) -> Result<&'bytes [u8], Error> {
    //         Ok(self.new_member)
    //     }

    //     fn encrypted_group_secrets(&self) -> Result<&HpkeCiphertext<'bytes>, Error> {
    //         Ok(&self.encrypted_groupsecrets)
    //     }
    // }

    // impl<'bytes> Welcome<'bytes> {
    //     fn suite(&self) -> Result<u16, Error> {
    //         u16::tls_deserialize_exact(self.suite)
    //     }

    //     fn secrets(&self) -> Result<&'bytes [EncryptedGroupSecrets<'bytes>], Error> {
    //         Ok(self.secrets)
    //     }

    //     fn encrypted_group_secrets(&self) -> Result<&'bytes [u8], Error> {
    //         Ok(self.encrypted_group_info)
    //     }
    // }

    /// A trait for zero-copy deserialization.
    ///
    /// This trait allows deserializing data that borrows from the input byte slice.
    pub trait DeserializeRef<'bytes>: Sized {
        /// Deserialize `Self` from `bytes`.
        ///
        /// Returns the deserialized instance and the remaining bytes.
        fn tls_deserialize_ref(bytes: &'bytes [u8]) -> Result<(Self, &'bytes [u8]), Error>;
    }

    pub trait Owned<RType, Type> {
        fn owned(&self) -> Type;
    }

    pub trait Reference<'a, RType, Type> {
        fn reference(&'a self) -> RType;
    }

    impl<'a> Owned<VLByteSlice<'a>, Vec<u8>> for VLByteSlice<'a> {
        fn owned(&self) -> Vec<u8> {
            self.0.to_vec()
        }
    }

    impl<'a> Reference<'a, VLByteSlice<'a>, Vec<u8>> for Vec<u8> {
        fn reference(&'a self) -> VLByteSlice<'a> {
            VLByteSlice(self.as_slice())
        }
    }

    // impl<'bytes> DeserializeRef<'bytes> for Welcome<'bytes> {
    //     fn tls_deserialize_ref(bytes: &'bytes [u8]) -> Result<(Self, &'bytes [u8]), Error> {
    //         if bytes.is_empty() {
    //             return Err(Error::EndOfStream);
    //         }

    //         let suite =

    //         Self {
    //             suite: todo!(),
    //             secrets: todo!(),
    //             encrypted_group_info: todo!(),
    //         }
    //         todo!()
    //     }
    // }

    // // --- Implementations for Primitives (Copy) ---

    // impl<'a> DeserializeRef<'a> for u8 {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         if bytes.is_empty() {
    //             return Err(Error::EndOfStream);
    //         }
    //         Ok((bytes[0], &bytes[1..]))
    //     }
    // }

    // impl<'a> DeserializeRef<'a> for u16 {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         if bytes.len() < 2 {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (val, remainder) = bytes.split_at(2);
    //         let val = u16::from_be_bytes(val.try_into().unwrap());
    //         Ok((val, remainder))
    //     }
    // }

    // impl<'a> DeserializeRef<'a> for u32 {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         if bytes.len() < 4 {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (val, remainder) = bytes.split_at(4);
    //         let val = u32::from_be_bytes(val.try_into().unwrap());
    //         Ok((val, remainder))
    //     }
    // }

    // impl<'a> DeserializeRef<'a> for u64 {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         if bytes.len() < 8 {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (val, remainder) = bytes.split_at(8);
    //         let val = u64::from_be_bytes(val.try_into().unwrap());
    //         Ok((val, remainder))
    //     }
    // }

    // // --- Implementations for Byte Slices (Zero-Copy) ---

    // impl<'a, T> DeserializeRef<'a> for TlsSliceU8<'a, T> {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         let (len, bytes) = u8::tls_deserialize_ref(bytes)?;
    //         let len = len as usize;
    //         if bytes.len() < len {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (slice, remainder) = bytes.split_at(len);
    //         Ok((TlsSliceU8::<'a, u8>(slice), remainder))
    //     }
    // }

    // // Wrapper for a 16-bit length prefixed byte slice
    // #[derive(Debug, PartialEq, Clone)]
    // pub struct TlsSliceU16<'a>(pub &'a [u8]);

    // impl<'a> DeserializeRef<'a> for TlsSliceU16<'a> {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         let (len, bytes) = u16::tls_deserialize_ref(bytes)?;
    //         let len = len as usize;
    //         if bytes.len() < len {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (slice, remainder) = bytes.split_at(len);
    //         Ok((TlsSliceU16(slice), remainder))
    //     }
    // }

    // // Helper for arrays (owned)
    // impl<'a, const N: usize> DeserializeRef<'a> for [u8; N] {
    //     fn tls_deserialize_ref(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
    //         if bytes.len() < N {
    //             return Err(Error::EndOfStream);
    //         }
    //         let (val, remainder) = bytes.split_at(N);
    //         let mut arr = [0u8; N];
    //         arr.copy_from_slice(val);
    //         Ok((arr, remainder))
    //     }
    // }
}
