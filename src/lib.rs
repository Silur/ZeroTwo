#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

extern crate wasm_bindgen;
use wasm_bindgen::prelude::*;
extern crate curve25519_dalek;
extern crate sha3;
extern crate rand;

use rand::rngs::{OsRng};
use crate::rand::RngCore;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use sha3::{Digest, Sha3_256};

lazy_static! {
    static ref G: RistrettoPoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.decompress().unwrap();
    static ref K: Scalar = Scalar::from_bytes_mod_order(G.compress().to_bytes());
}



#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct ECPoint {
    p: CompressedRistretto
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    private: Scalar,
    public: ECPoint
}

#[wasm_bindgen]
pub struct Proof {
    p: ECPoint,
    hmac: [u8; 32]
}

#[wasm_bindgen]
impl KeyPair {
    pub fn to_js(&self) -> JsValue {
        let mut buf = self.private.to_bytes().to_vec();
        buf.append(&mut self.public.to_bytes());
        JsValue::from_serde(&buf).unwrap()
    }

    pub fn from_js(v: &JsValue) -> KeyPair {
        let buf: Vec<u8> = v.into_serde().unwrap();
        let mut xbuf = [0u8; 32];
        let mut pbuf = [0u8; 32];
        for i in 0..32 {
            xbuf[i] = buf[i];
            pbuf[i] = buf[32+i];
        }
        let x = Scalar::from_canonical_bytes(xbuf).unwrap();
        let gx = CompressedRistretto::from_slice(&pbuf);
        KeyPair{private: x, public: ECPoint{p: gx}}
    }

	// we need a separate getter for wasm
    pub fn pubkey(&self) -> ECPoint {
        ECPoint {p: self.public.p }
    }
}   

impl ECPoint {
    pub fn decompress(&self) -> RistrettoPoint {
        self.p.decompress().unwrap()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.p.to_bytes().to_vec()
    }
}

#[wasm_bindgen]
impl ECPoint {
    pub fn to_js(&self) -> JsValue {
        JsValue::from_serde(&self.to_bytes()).unwrap()
    }

    pub fn from_js(v: &JsValue) -> ECPoint {
        let buf: Vec<u8> = v.into_serde().unwrap();
        let mut pbuf = [0u8; 32];
        for i in 0..32 {
            pbuf[i] = buf[i];
        }
        let p = CompressedRistretto::from_slice(&pbuf);
        ECPoint{p: p}
    }
}

#[wasm_bindgen]
impl Proof {
    pub fn to_js(&self) -> JsValue {
        let mut buf = self.p.to_bytes();
        buf.append(&mut self.hmac.to_vec());
        JsValue::from_serde(&buf).unwrap()
    }

    pub fn from_js(v: &JsValue) -> Proof {
        let buf: Vec<u8> = v.into_serde().unwrap();
        let mut pbuf = [0u8; 32];
        let mut hbuf = [0u8; 32];
        for i in 0..32 {
            pbuf[i] = buf[i];
            hbuf[i] = buf[32+i];
        }
        let p = CompressedRistretto::from_slice(&pbuf);
        Proof{p: ECPoint{p: p}, hmac: hbuf}
    }
}

fn sha3(data: &Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.input(data);
    let r = hasher.result();
    let mut ret = [0u8; 32];
    for i in 0..32 {
        ret[i] = r[i];
    }
    ret
}
fn hash_to_scalar(args: &mut [&Vec<u8>]) -> Scalar {
    let mut input = args[0].clone();
    for i in 0..args.len() {
        input.append(&mut args[i].clone());
    }
    let x = sha3(&input);
    Scalar::from_bytes_mod_order(x)
}

// RFC 2104
fn hmac(key: [u8; 32], msg: &Vec<u8>) -> [u8; 32] {
    let opad = vec![0x5c; 32];
    let ipad = vec![0x36; 32];
    let mut p1 = vec![0u8;32];
    let mut p2 = vec![0u8;32];
    for i in 0..32 {
        p1[i] = key[i] ^ opad[i];
        p2[i] = key[i] ^ ipad[i];
    }
    p2.append(&mut msg.clone());
    p1.append(&mut sha3(&p2).to_vec());
    sha3(&p1)
}

#[wasm_bindgen]
pub fn register(user_id: &[u8],
                server_id: &[u8], 
                master_secret: &[u8]) -> KeyPair {
    let x = hash_to_scalar(&mut [&user_id.to_vec(), 
                                 &server_id.to_vec(), 
                                 &master_secret.to_vec()]);
    let gx = *G*x;
	// we need to discard the ephemeral secret, it is recovered by the verifier
    KeyPair {private: Scalar::zero(), public: ECPoint{p: gx.compress()}}
}

#[wasm_bindgen]
pub fn gen_challenge(verifier: &ECPoint) -> KeyPair {
    let mut bbytes = [0u8; 32];
    OsRng.fill_bytes(&mut bbytes);
    let b = Scalar::from_bytes_mod_order(bbytes);
    let kv = *K*verifier.decompress();
    let challenge = kv + *G*b;
    KeyPair {private: b, public: ECPoint {p: challenge.compress()}}
}

#[wasm_bindgen]
pub fn prove(user_id: &[u8],
             server_id: &[u8],
             challenge: &ECPoint,
             master_secret: &[u8],
             duration: u32) -> Proof {
    let x = hash_to_scalar(&mut [&user_id.to_vec(), 
                           &server_id.to_vec(), 
                           &master_secret.to_vec()]);
    let mut abytes = [0u8; 32];
    OsRng.fill_bytes(&mut abytes);
    let a = Scalar::from_bytes_mod_order(abytes);
    let ga = *G*a;
    let u = hash_to_scalar(&mut [&ga.compress().to_bytes().to_vec(), 
                           &challenge.to_bytes().to_vec()]);
    let ckgx = challenge.decompress() - (*K*(*G*x));
    let s = ckgx*a + ckgx*(u*x);
    let k = sha3(&s.compress().to_bytes().to_vec());
    let mut input = user_id.to_vec();
    input.append(&mut server_id.to_vec());
    input.append(&mut ga.compress().to_bytes().to_vec());
    input.append(&mut challenge.to_bytes());
    input.append(&mut duration.to_be_bytes().to_vec());
    let m = hmac(k, &input);
    Proof {p: ECPoint {p: ga.compress()} , hmac: m}
}

#[wasm_bindgen]
pub fn verify(user_id: &[u8],
              server_id: &[u8],
              challenge: KeyPair,
              proof: Proof,
              verifier: &ECPoint,
              duration: u32) -> bool {
    let u = hash_to_scalar(&mut [&proof.p.to_bytes(), 
                           &challenge.public.to_bytes()]);
    let avub = (proof.p.decompress() + (u*verifier.decompress()))*challenge.private;
    let k = sha3(&avub.compress().to_bytes().to_vec());
    let mut input = user_id.to_vec();
    input.append(&mut server_id.to_vec());
    input.append(&mut proof.p.to_bytes().to_vec());
    input.append(&mut challenge.public.to_bytes());
    input.append(&mut duration.to_be_bytes().to_vec());
    let m = hmac(k, &input);
    proof.hmac == m
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let master_secret = "Keep my secret darling!".as_bytes().to_vec();
        let user_id = "Hiro".as_bytes().to_vec();
        let server_id = "Strelizia".as_bytes().to_vec();
        let duration = 10000u32;
        let verifier = register(&user_id, &server_id, &master_secret);
        let challenge = gen_challenge(&verifier.public);
        let proof = prove(&user_id, &server_id, &challenge.public, 
                                       &master_secret, duration);
        assert!(verify(&user_id, &server_id, challenge, proof, &verifier.public, duration));
    }
    
    #[test]
    fn wasm_helpers() {
    }

/*    #[bench]
    fn benchmark(b: &mut Bencher) {
        b.iter(|| it_works());
    }*/
}
