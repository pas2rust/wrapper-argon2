use wrapper_argon2::wrapper::{Argon2Trait, WrapperArgon2};

#[test]
fn argon2_default_gen_hash_and_verify_password() {
    let mut wrapper = WrapperArgon2::new("12345".to_string(), None);
    let hash = wrapper.default_encode().expect("hash error");
    wrapper.set_hash(Some(hash));
    let verify = wrapper.default_verify_password();
    match verify {
        Ok(ok) => assert!(ok),
        Err(err) => {
            wrapper.print_err(err.as_str());
            assert!(false)
        }
    };
}
