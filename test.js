const user_id = 'hiro'
const server_id = 'Strelizia'
const master_secret = 'Keep my secret darling!'
const duration = 10000
const zeroTwo = require('./pkg/zerotwo.js')

const verifier = zeroTwo.register(user_id, server_id, master_secret)
const challenge = zeroTwo.gen_challenge(verifier.pubkey())
const proof = zeroTwo.prove(user_id, server_id, challenge.pubkey(),
                            master_secret, duration)
const authenticated = zeroTwo.verify(user_id, server_id, challenge, 
                                     proof, verifier.pubkey(), duration)
if (authenticated) {
  console.log("you are my darling!");
}
