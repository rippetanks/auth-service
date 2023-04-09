use argon2::Argon2;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use scrypt::{Params, Scrypt};
use scrypt::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use sha2::{Sha256, Digest};

pub fn hash_pwd(pwd: &str) -> Option<String> {
    let params = Params::recommended();
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Scrypt.hash_password_customized(pwd.as_bytes(),
                                                          Some(scrypt::ALG_ID),
                                                          None,
                                                          params,
                                                          salt.as_salt());
    if hashed_password.is_err() {
        error!("can not hash password: {}", hashed_password.unwrap_err());
        None
    } else {
        Some(hashed_password.unwrap().to_string())
    }
}

pub fn hash_secret(secret: &str) -> Option<String> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hashed_secret = argon2.hash_password(secret.as_bytes(), &salt);
    if hashed_secret.is_err() {
        error!("can not hash secret: {}", hashed_secret.unwrap_err());
        None
    } else {
        Some(hashed_secret.unwrap().to_string())
    }
}

pub fn hash_pwd_check(pwd: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(&hash);
    match parsed_hash {
        Ok(pwd_hash) if Scrypt.verify_password(pwd.as_bytes(), &pwd_hash).is_ok() => true,
        _ => false
    }
}

pub fn hash_secret_check(secret: &str, hash: &str) -> bool {
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&hash);
    match parsed_hash {
        Ok(secret_hash) if argon2.verify_password(secret.as_bytes(), &secret_hash).is_ok() => true,
        _ => false
    }
}

pub fn generate_secure_secret() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(secret)
}

pub fn generate_secure_code() -> String {
    let mut code = [0u8; 16];
    OsRng.fill_bytes(&mut code);
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(code)
}

pub fn hash_code_verifier(to_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(to_hash.as_bytes());
    let result = hasher.finalize();
    let engine = base64::engine::general_purpose::URL_SAFE;
    engine.encode(result)
}