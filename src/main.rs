fn main() {
    println!("Hello, world!");
}


#[cfg(test)]
mod tests {
    use curv::arithmetic::{Modulo, Samplable};
    use curv::BigInt;
    use elgamal::{ElGamal, ElGamalCiphertext, ElGamalKeyPair, ElGamalPP};
    use elgamal::rfc7919_groups::SupportedGroups;

    #[test]
    fn encode_name() {
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let mut name = "richard".as_bytes();

        let (int_bytes, _) = name.split_at(std::mem::size_of::<u32>());
        let message = u32::from_be_bytes(int_bytes.try_into().unwrap());
        let message_bn = BigInt::from(message);
        let message_in_field = message_bn.modulus(&pp.q);
        let cipher = ElGamal::encrypt(&message_in_field, &key_pair.pk).unwrap();
        let message_prime = ElGamal::decrypt(&cipher, &key_pair.sk).unwrap();
        assert_eq!(message_bn, message_prime);
        println!(
            "basic encryption: message: {}, decrypted: {}",
            message, message_prime
        );
    }

    #[test]
    fn encode_name_no_encrypt() {
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let pk = key_pair.pk;
        let sk = key_pair.sk;
        let mut name = "richard".as_bytes();

        let (int_bytes, _) = name.split_at(std::mem::size_of::<u32>());
        let message = u32::from_be_bytes(int_bytes.try_into().unwrap());
        let message_bn = BigInt::from(message);
        let message_in_field = message_bn.modulus(&pp.q);
        let y = BigInt::sample_below(&pk.pp.q);
        let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &message_in_field, &pk.pp.p);
        let cipher = ElGamalCiphertext {
            c1,
            c2,
            pp,
        };
        let message_prime = ElGamal::decrypt(&cipher, &sk).unwrap();
        assert_eq!(message_bn, message_prime);
        println!(
            "basic encryption: message: {}, decrypted: {}",
            message, message_prime
        );
    }

    #[test]
    fn homomorphic_mul() {

        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let pk = key_pair.pk;
        let sk = key_pair.sk;

        let m1 = BigInt::from(3);
        let y = BigInt::sample_below(&pk.pp.q);
        let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &m1, &pk.pp.p);

        let cipher1 = ElGamalCiphertext {
            c1,
            c2,
            pp: pp.clone(),
        };

        let m1 = BigInt::from(5);
        let y = BigInt::sample_below(&pk.pp.q);
        let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &m1, &pk.pp.p);

        let cipher2 = ElGamalCiphertext {
            c1,
            c2,
            pp: pp.clone(),
        };


        let result = ElGamalCiphertext {
            c1: BigInt::mod_mul(&cipher1.c1, &cipher2.c1, &cipher1.pp.p ),
            c2: BigInt::mod_mul(&cipher1.c2, &cipher2.c2, &cipher1.pp.p ),
            pp,
        };

        let message_prime = ElGamal::decrypt(&result, &sk).unwrap();
        assert_eq!(BigInt::from(15), message_prime);
    }
}