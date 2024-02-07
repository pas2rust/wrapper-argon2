use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use darth_rust::DarthRust;

#[derive(Debug, DarthRust, Clone)]
pub struct WrapperArgon2 {
    pub password: String,
    pub hash: Option<String>,
}

pub trait Argon2Trait {
    fn default_encode(&self) -> Result<String, String>;
    fn default_verify_password(&self) -> Result<bool, String>;
}

impl Argon2Trait for WrapperArgon2 {
    fn default_encode(&self) -> Result<String, String> {
        let password = &self.password;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt);
        match password_hash {
            Ok(hash) => Ok(hash.to_string()),
            Err(err) => Err(err.to_string()),
        }
    }
    fn default_verify_password(&self) -> Result<bool, String> {
        let original_password = &self.password;
        let encoded_hash = &self.hash.as_ref().expect("hash must be provided");
        let parsed_hash = PasswordHash::new(encoded_hash.as_str())
            .map_err(|e| format!("Invalid hash format: {}", e))?;
        let argon2 = Argon2::default();
        argon2
            .verify_password(original_password.as_bytes(), &parsed_hash)
            .map_err(|_| "Password verification failed".to_string())
            .map(|_| true)
    }
}
