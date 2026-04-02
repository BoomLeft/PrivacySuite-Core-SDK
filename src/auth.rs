//! OPAQUE zero-knowledge password authentication (aPAKE).
//!
//! The server **never** sees the user's password -- not during registration,
//! not during login. Instead the server stores a cryptographic envelope
//! produced by the OPAQUE protocol, and authentication is completed through
//! an oblivious pseudorandom function (OPRF) exchange followed by a
//! triple-Diffie-Hellman key agreement.
//!
//! This module exposes client-side helpers only. The SDK runs on the user's
//! device; the server counterpart lives in the relay service.
//!
//! # Wire format
//!
//! Every `Vec<u8>` returned as a "message to send" is the **raw** serialised
//! OPAQUE protocol message.  The transport layer (TLS / Tor) is responsible
//! for framing.

use std::fmt;

use opaque_ke::errors::ProtocolError;
use opaque_ke::ksf::Identity;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CipherSuite,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Cipher-suite definition
// ---------------------------------------------------------------------------

/// Concrete OPAQUE cipher suite used throughout `PrivacySuite`.
///
/// * OPRF + KE group: Ristretto255
/// * Key exchange: Triple-DH
/// * Key-stretching: `Identity` (Argon2 is applied *before* the password
///   reaches the OPAQUE layer via [`crate::crypto::keys::derive_key`]).
struct PrivacySuite;

impl CipherSuite for PrivacySuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Identity;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from the OPAQUE authentication flow.
#[derive(Debug)]
pub enum AuthError {
    /// The OPAQUE protocol state machine detected an invalid transition.
    Protocol,
    /// A wire message could not be deserialised.
    InvalidMessage,
    /// A lower-level cryptographic primitive failed.
    Crypto(CryptoError),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => f.write_str("OPAQUE protocol error"),
            Self::InvalidMessage => f.write_str("invalid OPAQUE message"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CryptoError> for AuthError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<ProtocolError> for AuthError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::SerializationError => Self::InvalidMessage,
            _ => Self::Protocol,
        }
    }
}

// ---------------------------------------------------------------------------
// Session key wrapper (zeroizing)
// ---------------------------------------------------------------------------

/// An authenticated session key produced by a successful OPAQUE login.
///
/// The inner bytes are zeroised on drop and never appear in `Debug` output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    bytes: Vec<u8>,
}

impl SessionKey {
    /// View the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(***)")
    }
}

// ---------------------------------------------------------------------------
// Opaque state wrappers
// ---------------------------------------------------------------------------

/// Client-side state kept between `registration_start` and
/// `registration_finish`.
///
/// Holds the OPAQUE protocol state **and** a zeroising copy of the password
/// (needed by the finish step).  The password is zeroised when the finish
/// function consumes this state.
pub struct ClientRegistrationState {
    inner: ClientRegistration<PrivacySuite>,
    #[doc(hidden)]
    password: ZeroizingPassword,
}

impl fmt::Debug for ClientRegistrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // PEN-04: Never print opaque-ke internal state — it contains
        // protocol secrets (OPRF blinding factor, etc.).
        f.write_str("ClientRegistrationState(***)")
    }
}

/// Client-side state kept between `login_start` and `login_finish`.
///
/// Holds the OPAQUE protocol state **and** a zeroising copy of the password
/// (needed by the finish step).  The password is zeroised when the finish
/// function consumes this state.
pub struct ClientLoginState {
    inner: ClientLogin<PrivacySuite>,
    #[doc(hidden)]
    password: ZeroizingPassword,
}

impl fmt::Debug for ClientLoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientLoginState(***)")
    }
}

/// A password buffer that zeroises itself on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizingPassword(Vec<u8>);

// ---------------------------------------------------------------------------
// Client-side API
// ---------------------------------------------------------------------------

/// Begin OPAQUE registration.
///
/// Returns the client state to hold onto and the serialised
/// [`RegistrationRequest`](opaque_ke::RegistrationRequest) to send to the
/// server.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] if the OPRF blinding step fails, or
/// [`AuthError::Crypto`] if the OS entropy source is unavailable.
pub fn registration_start(password: &[u8]) -> Result<(ClientRegistrationState, Vec<u8>), AuthError> {
    let mut rng = OsRng;
    let result = ClientRegistration::<PrivacySuite>::start(&mut rng, password)?;
    let message = result.message.serialize().to_vec();
    Ok((
        ClientRegistrationState {
            inner: result.state,
            password: ZeroizingPassword(password.to_vec()),
        },
        message,
    ))
}

/// Finish OPAQUE registration.
///
/// Takes the state from [`registration_start`] and the server's serialised
/// [`RegistrationResponse`](opaque_ke::RegistrationResponse). Returns the
/// serialised [`RegistrationUpload`](opaque_ke::RegistrationUpload) to send
/// back to the server. Once the server processes this message the user is
/// registered.
///
/// # Errors
///
/// Returns [`AuthError::InvalidMessage`] if the server response cannot be
/// deserialised, or [`AuthError::Protocol`] if the OPAQUE envelope
/// construction fails.
pub fn registration_finish(
    state: ClientRegistrationState,
    server_response: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let mut rng = OsRng;
    let response = opaque_ke::RegistrationResponse::<PrivacySuite>::deserialize(server_response)?;
    let result = state.inner.finish(
        &mut rng,
        &state.password.0,
        response,
        ClientRegistrationFinishParameters::default(),
    )?;
    // `state.password` is dropped here and zeroised via ZeroizeOnDrop
    Ok(result.message.serialize().to_vec())
}

/// Begin OPAQUE login.
///
/// Returns the client state to hold onto and the serialised
/// [`CredentialRequest`](opaque_ke::CredentialRequest) to send to the server.
///
/// # Errors
///
/// Returns [`AuthError::Protocol`] if the OPRF blinding step fails, or
/// [`AuthError::Crypto`] if the OS entropy source is unavailable.
pub fn login_start(password: &[u8]) -> Result<(ClientLoginState, Vec<u8>), AuthError> {
    let mut rng = OsRng;
    let result = ClientLogin::<PrivacySuite>::start(&mut rng, password)?;
    let message = result.message.serialize().to_vec();
    Ok((
        ClientLoginState {
            inner: result.state,
            password: ZeroizingPassword(password.to_vec()),
        },
        message,
    ))
}

/// Finish OPAQUE login.
///
/// Takes the state from [`login_start`] and the server's serialised
/// [`CredentialResponse`](opaque_ke::CredentialResponse). On success returns
/// an authenticated [`SessionKey`] that matches the server's session key.
///
/// # Errors
///
/// Returns [`AuthError::InvalidMessage`] if the server response cannot be
/// deserialised, or [`AuthError::Protocol`] if the password was wrong or the
/// key-exchange verification failed.
pub fn login_finish(
    state: ClientLoginState,
    server_response: &[u8],
) -> Result<SessionKey, AuthError> {
    let response = opaque_ke::CredentialResponse::<PrivacySuite>::deserialize(server_response)?;
    let result = state.inner.finish(
        &state.password.0,
        response,
        ClientLoginFinishParameters::default(),
    )?;
    // `state.password` is dropped here and zeroised via ZeroizeOnDrop
    Ok(SessionKey {
        bytes: result.session_key.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
    };
    use rand::rngs::OsRng;

    /// Identifier used as the "username" in the server-side OPAQUE calls.
    const USER_ID: &[u8] = b"alice@boomleft.example";

    /// Run a full registration flow using the client helpers + raw server
    /// calls, returning the serialised password file.
    fn register(
        server_setup: &ServerSetup<PrivacySuite>,
        password: &[u8],
    ) -> Vec<u8> {
        // 1. Client starts registration
        let (client_state, reg_request_bytes) =
            registration_start(password).expect("registration_start");

        // 2. Server processes the request
        let reg_request =
            opaque_ke::RegistrationRequest::<PrivacySuite>::deserialize(&reg_request_bytes)
                .expect("deserialize RegistrationRequest");
        let server_reg_result =
            ServerRegistration::<PrivacySuite>::start(server_setup, reg_request, USER_ID)
                .expect("ServerRegistration::start");
        let server_response_bytes = server_reg_result.message.serialize().to_vec();

        // 3. Client finishes registration
        let upload_bytes =
            registration_finish(client_state, &server_response_bytes)
                .expect("registration_finish");

        // 4. Server finishes registration and stores password file
        let upload =
            opaque_ke::RegistrationUpload::<PrivacySuite>::deserialize(&upload_bytes)
                .expect("deserialize RegistrationUpload");
        let password_file = ServerRegistration::<PrivacySuite>::finish(upload);
        password_file.serialize().to_vec()
    }

    /// Run a full login flow.  Returns the client session key on success.
    fn login(
        server_setup: &ServerSetup<PrivacySuite>,
        password_file_bytes: &[u8],
        password: &[u8],
    ) -> Result<SessionKey, AuthError> {
        // 1. Client starts login
        let (client_state, cred_request_bytes) = login_start(password)?;

        // 2. Server processes the login request
        let cred_request =
            opaque_ke::CredentialRequest::<PrivacySuite>::deserialize(&cred_request_bytes)
                .expect("deserialize CredentialRequest");
        let password_file =
            ServerRegistration::<PrivacySuite>::deserialize(password_file_bytes)
                .expect("deserialize password file");
        let mut rng = OsRng;
        let server_login_result = ServerLogin::start(
            &mut rng,
            server_setup,
            Some(password_file),
            cred_request,
            USER_ID,
            ServerLoginStartParameters::default(),
        )
        .expect("ServerLogin::start");
        let server_response_bytes = server_login_result.message.serialize().to_vec();

        // 3. Client finishes login
        let session_key = login_finish(client_state, &server_response_bytes)?;

        // 4. Server finishes login (verify the finalization message)
        // In a real system the client would send client_login_finish_result.message
        // to the server here. We skip that for brevity since we are testing the
        // client side.

        Ok(session_key)
    }

    #[test]
    fn full_registration_and_login() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<PrivacySuite>::new(&mut rng);
        let password = b"correct horse battery staple";

        let pf = register(&server_setup, password);
        let session_key = login(&server_setup, &pf, password)
            .expect("login should succeed with correct password");

        // Session key should be non-empty.
        assert!(
            !session_key.as_bytes().is_empty(),
            "session key must not be empty"
        );
    }

    #[test]
    fn wrong_password_fails_login() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<PrivacySuite>::new(&mut rng);

        let pf = register(&server_setup, b"correct password");
        let result = login(&server_setup, &pf, b"wrong password");

        assert!(result.is_err(), "login with wrong password must fail");
    }

    #[test]
    fn session_key_debug_does_not_leak() {
        let key = SessionKey {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let debug = format!("{key:?}");
        assert!(
            !debug.contains("DEAD"),
            "Debug output must not contain key material"
        );
        assert!(
            !debug.contains("dead"),
            "Debug output must not contain key material"
        );
        assert_eq!(debug, "SessionKey(***)");
    }
}
