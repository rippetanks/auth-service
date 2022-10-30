use rand_core::OsRng;
use scrypt::{Params, Scrypt};
use scrypt::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

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

pub fn hash_check(pwd: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(&hash);
    match parsed_hash {
        Ok(pwd_hash) if Scrypt.verify_password(pwd.as_bytes(), &pwd_hash).is_ok() => true,
        _ => false
    }
}