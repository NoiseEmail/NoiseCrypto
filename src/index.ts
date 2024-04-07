import * as util from './util';
import * as symmetric from './sym';
import * as ecc from './ecc';
import Ecc from './ecc';
import * as ies from './ies';
import Ies from './ies'


export {
    util,
    symmetric,
    ecc,
    Ecc,
    ies,
    Ies
};



const ies_config = new Ies();
const keys = ies_config.key_pair();
const data = 'Hello, World!';
const encrypted = ies_config.encrypt(data, keys.public_key.key);

const stored_data = Ies.buffer_to_hex(encrypted);
const stored_key = keys.private_key.toString();

const decrypted = ies_config.decrypt(stored_data, stored_key);
console.log('Decrypted:', Ies.buffer_to_string(decrypted));




// const curve = ecc.configuration.p521();

// const private_key = curve.private_key()
// const public_key = private_key.public_key;

// const shared = crypto.shared_secret.derive_encryption_key(public_key.key, curve);


// const data = 'Hello, World!';
// const data_buf = new TextEncoder().encode(data);

// const encrypted = symmetric.encrypt(
//     symmetric.functions.gcm_aes, 
//     data_buf, 
//     shared.shared_secret
// );

// console.log('Encrypted:', encrypted.hex);


// // const deserialized = symmetric.serialize.deserialize(encrypted.data);
// // const serialized = symmetric.serialize.serialize(
// //     deserialized.data,
// //     deserialized.nonce,
// //     symmetric.functions.gcm_aes
// // );
// // console.log('Encrypted:', serialized.hex);

// const decrypted = symmetric.decrypt(
//     symmetric.functions.gcm_aes, 
//     encrypted.data, 
//     shared.shared_secret
// );

// console.log('Decrypted:', new TextDecoder().decode(decrypted));
