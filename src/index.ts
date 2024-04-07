import * as crypto from './util';
import * as symmetric from './sym';
import * as ecc from './ecc';




const curve = ecc.configuration.p521();

const private_key = curve.private_key()
const public_key = private_key.public_key;

const shared = crypto.shared_secret.derive_encryption_key(public_key.key, curve);


const data = 'Hello, World!';
const data_buf = new TextEncoder().encode(data);

const encrypted = symmetric.encrypt(
    symmetric.functions.gcm_aes, 
    data_buf, 
    shared.shared_secret
);

console.log('Encrypted:', encrypted.hex);


// const deserialized = symmetric.serialize.deserialize(encrypted.data);
// const serialized = symmetric.serialize.serialize(
//     deserialized.data,
//     deserialized.nonce,
//     symmetric.functions.gcm_aes
// );
// console.log('Encrypted:', serialized.hex);

const decrypted = symmetric.decrypt(
    symmetric.functions.gcm_aes, 
    encrypted.data, 
    shared.shared_secret
);

console.log('Decrypted:', new TextDecoder().decode(decrypted));
