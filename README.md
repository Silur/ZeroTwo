# ZeroTwo

This is an elliptic curve instantiation of the [authentication scheme](https://arxiv.org/abs/1907.12398v1) designed by Laurent Chuat, Sarah Plocher, Adrian Perrig.

It is a state-of-the-art user-friendly protocol that combines the best properties of SRS, PAKE, and 2FA. ![](https://i.imgur.com/YNioNXq.png)

## Usage

```rust
// Initial setup
let master_secret = "Keep my secret darling!".as_bytes().to_vec();
let user_id = "Hiro".as_bytes().to_vec();
let server_id = "Strelizia".as_bytes().to_vec();
let duration = 10000u32;
// On registration
let verifier = register(&user_id, &server_id, &master_secret);
// Called on every login attempt by the server
// It's the server's responsibility to look up the verifier data associated with a user
// This challenge can be shown on independent plaintext channels like QR codes
let challenge = gen_challenge(&verifier.public);
// Called on every login attempt by the client
let proof = prove(&user_id, &server_id, &challenge.public,
				   &master_secret, duration);
// Verification
assert!(verify(&user_id, &server_id, challenge, proof, &verifier.public, duration));
```

## Wasm bindings

If you have [wasm-pack](https://rustwasm.github.io/wasm-pack/) set up you can build the library using:

`wasm-pack build`

This generates the bindings under `/pkg` which you can use as seen in `test.js`

```javascript	
const user_id = 'hiro'
const server_id = 'Strelizia'
const master_secret = 'Keep my secret darling!'
const duration = 10000
const zeroTwo = require('./pkg/zerotwo.js')

const verifier = zeroTwo.register(user_id, server_id, master_secret)
// save as verifier.to_js()
// load as zeroTwo.KeyPair.from_js(...)
const challenge = zeroTwo.gen_challenge(verifier.pubkey())
// save as challenge.to_js()
// load as zeroTwo.KeyPair.from_js(...)
const proof = zeroTwo.prove(user_id, server_id, challenge.pubkey(),
                            master_secret, duration)
// save as proof.to_js()
// load as zeroTwo.Proof.from_js(...)
const authenticated = zeroTwo.verify(user_id, server_id, challenge, 
                                     proof, verifier.pubkey(), duration)
if (authenticated) {
  console.log("you are my darling!");
}
```

## Disclaimer

This distribution includes cryptographic software. The country in  which you currently reside may have restrictions on the import,  possession, use, and/or re-export to another country, of encryption  software. BEFORE using any encryption software, please check your  country's laws, regulations and policies concerning the import,  possession, or use, and re-export of encryption software, to see if this is permitted. See http://www.wassenaar.org/ for more information.
