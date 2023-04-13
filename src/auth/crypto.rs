use argon2::{Argon2, password_hash};
use base64::Engine;
use rand_core::{OsRng, RngCore};
use scrypt::Scrypt;
use scrypt::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use sha2::{Sha256, Digest};

/// Use Scrypt and a 16-bytes salt to hash a password
pub fn hash_pwd(pwd: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    match Scrypt.hash_password(pwd.as_bytes(), &salt) {
        Ok(hashed) => Some(hashed.to_string()),
        Err(e) => {
            error!("can not hash password - cause: {}", e);
            None
        }
    }
}

/// Check if password match the hashed password using Scrypt
pub fn hash_pwd_check(pwd: &str, pwd_hash: &str) -> bool {
    match PasswordHash::new(pwd_hash) {
        Ok(hash) if Scrypt.verify_password(pwd.as_bytes(), &hash).is_ok() => true,
        _ => false
    }
}

/// Use KDF Argon2id (hybrid version) to derive a key using a 16-bytes salt
pub fn hash_secret(secret: &str) -> Result<String, password_hash::Error> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    argon2.hash_password(secret.as_bytes(), &salt)
        .map(|hashed| hashed.to_string())
}

/// Check if secret match the hashed secret using Argon2id
pub fn hash_secret_check(secret: &str, hashed_secret: &str) -> bool {
    let argon2 = Argon2::default();
    match PasswordHash::new(hashed_secret) {
        Ok(hash) if argon2.verify_password(secret.as_bytes(), &hash).is_ok() => true,
        _ => false
    }
}

/// Generate a secure 36 bytes secret (base64 encoded)
pub fn generate_secure_secret() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(secret)
}

/// Generate a secure 16 bytes code (base64 encoded)
pub fn generate_secure_code() -> String {
    let mut code = [0u8; 16];
    OsRng.fill_bytes(&mut code);
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(code)
}

/// Hash an OAuth2 code verifier (SHA-256 base64 URL safe)
pub fn hash_code_verifier(to_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(to_hash.as_bytes());
    let result = hasher.finalize();
    let engine = base64::engine::general_purpose::URL_SAFE;
    engine.encode(result)
}