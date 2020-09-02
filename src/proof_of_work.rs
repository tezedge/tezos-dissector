use crypto::blake2b;
use num_bigint::BigUint;
use std::convert::TryFrom;

pub const DEFAULT_TARGET: f64 = 24.0;

pub fn generate_proof_of_work(public_key: &[u8; 0x20], target: f64) -> Result<[u8; 0x18], ()> {
    let mut data = [0; 0x20 + 0x18];
    data[..0x20].clone_from_slice(public_key.as_ref());

    let target_number = make_target(target);
    loop {
        if let Ok(()) = check_proof_of_work_inner(data.as_ref(), &target_number) {
            let mut nonce = [0; 0x18];
            nonce.clone_from_slice(&data[0x20..]);
            return Ok(nonce);
        } else {
            // the code might look obscure,
            // but it just treat `data[0x20..0x38]` as an 192-bit integer and increment it

            let mut a = u64::from_be_bytes(<[u8; 8]>::try_from(&data[0x20..0x28]).unwrap());
            let mut b = u64::from_be_bytes(<[u8; 8]>::try_from(&data[0x28..0x30]).unwrap());
            let mut c = u64::from_be_bytes(<[u8; 8]>::try_from(&data[0x30..0x38]).unwrap());

            if c == u64::MAX {
                if b == u64::MAX {
                    if a == u64::MAX {
                        return Err(());
                    } else {
                        a += 1;
                        b = 0;
                        c = 0;
                    }
                } else {
                    b += 1;
                    c = 0;
                }
            } else {
                c += 1;
            }

            data[0x20..0x28].clone_from_slice(a.to_be_bytes().as_ref());
            data[0x28..0x30].clone_from_slice(b.to_be_bytes().as_ref());
            data[0x30..0x38].clone_from_slice(c.to_be_bytes().as_ref());
        }
    }
}

pub fn check_proof_of_work(data: &[u8], target: f64) -> Result<(), ()> {
    let target_number = make_target(target);
    check_proof_of_work_inner(data, &target_number)
}

pub fn check_proof_of_work_detached(pk: &[u8; 0x20], pow: &[u8; 0x18], target: f64) -> Result<(), ()> {
    let mut data = [0; 0x20 + 0x18];
    data[..0x20].clone_from_slice(pk.as_ref());
    data[0x20..].clone_from_slice(pow.as_ref());
    check_proof_of_work(data.as_ref(), target)
}

fn check_proof_of_work_inner(data: &[u8], target_number: &BigUint) -> Result<(), ()> {
    let hash = blake2b::digest_256(data);
    let hash_number = BigUint::from_bytes_le(hash.as_ref());
    if hash_number.le(target_number) {
        Ok(())
    } else {
        Err(())
    }
}

fn make_target(target: f64) -> BigUint {
    assert!((0.0 .. 256.0).contains(&target));
    let (frac, shift) = (target.fract(), target.floor() as u64);
    let m = if frac.abs() < std::f64::EPSILON {
        (1 << 54) - 1
    } else {
        2.0f64.powf(54.0 - frac) as u64
    };
    let m = BigUint::from(m);
    if shift < 202 {
        (m << (202 - shift)) | ((BigUint::from(1u64) << (202 - shift)) - BigUint::from(1u64))
    } else {
        m >> (shift - 202)
    }
}

// TODO: test `BigUint::from_bytes_le` is the same as `Z.of_bits`
#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use super::{generate_proof_of_work, check_proof_of_work, DEFAULT_TARGET};

    #[test]
    fn simple_check() {
        let data = hex::decode("\
            d8246d13d0270cbfff4046b6d94b05ab19920bc5ad9fb77f3e945c40b340e874\
            d1d0ebd55784bc92852d913dbf0fb5152d505b567d930fb2\
        ").unwrap();
        check_proof_of_work(data.as_ref(), DEFAULT_TARGET).unwrap();
    }

    #[test]
    fn simple_generate() {
        let pk = hex::decode("\
            d8246d13d0270cbfff4046b6d94b05ab19920bc5ad9fb77f3e945c40b340e874\
        ").unwrap();
        let pk_slice = <&[u8; 0x20]>::try_from(pk.as_slice()).unwrap();
        let _ = generate_proof_of_work(pk_slice, 20.0).unwrap();
    }
}
