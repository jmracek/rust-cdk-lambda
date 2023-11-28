use lambda_http::{Body, Error, Response};
use rand::rngs::OsRng;
use rand::RngCore;

// Obviously change this
static PEPPER: &[u8]  = b"PEPPER";
const BCRYPT_COST: u32 = 10;

/// Utility for building a response with a fixed error code and message.
pub fn respond_error(status_code: u16, message: &str) -> Result<Response<Body>, Error> {
    let error_message = format!("{{\"error_message\": \"{}\"}}", message).to_string();
    Ok(Response::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(error_message.into())
        .map_err(Box::new)?)
}

/// This utility computes the verifying hash.  It inserts pepper into the password
/// then computes the bcrypt hash.
pub fn compute_verifying_hash(salt: [u8; 16], password: String) -> [u8; 24] {
    let peppered_password = {
        let mut peppered = password
            .into_bytes();
        peppered.extend_from_slice(PEPPER);
        peppered
    };

    bcrypt::bcrypt(BCRYPT_COST, salt, &peppered_password[..])
}

/// This utility generates salt for each user from random bytes obtained from the OS
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}
