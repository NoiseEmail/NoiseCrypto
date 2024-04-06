import * as crypto from './util';
import * as ecc from './ecc';



const private_key_hex = 'f517182b01b3b682fa8d84b638de949d3bd9a5608ecabe96da6c0ab01c5de6cb86b06209dee8f1149ae2e96071919ed3144e16cf79fae7b55ebed65b8a08c90d25';
const private_key_bytes = Buffer.from(private_key_hex, 'hex');

const curve = ecc.configuration.p521();

const private_key = curve.private_key(private_key_bytes)
const public_key = private_key.public_key;

const shared = crypto.shared_secret.derive_encryption_key(public_key.key, curve);
console.log('Shared Secret:', Buffer.from(shared.shared_secret).toString('hex'));


const shared2 = crypto.shared_secret.derive_decryption_key(private_key.key, shared.ephemeral_key, curve);
console.log('Shared Secret:', Buffer.from(shared2.shared_secret).toString('hex'));