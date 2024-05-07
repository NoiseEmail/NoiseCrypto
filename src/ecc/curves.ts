import { x25519 } from '@noble/curves/ed25519';
import { secp256k1} from '@noble/curves/secp256k1';
import { concatBytes } from '@noble/ciphers/utils';
import { p521 } from '@noble/curves/p521';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { Configutaion } from './configuration';
import { derive_key } from '../util/shared_secret';
import { HashFunction } from '../util/hash';
import { hkdf } from '@noble/hashes/hkdf';



type Curve = {
    name: string;
    public_key_length: number;
    private_key_length: number;
    curve: {};

    get_shared_point(private_key: Uint8Array, public_key: Uint8Array): Uint8Array;
    get_shared_secret(ephemeral_point: Uint8Array, shared_point: Uint8Array, configuration: Configutaion): Uint8Array;
    get_public_key(private_key: Uint8Array): Uint8Array;
    valid_private_key(private_key: Uint8Array): boolean;
    generate_secret(): Uint8Array;
    from_seed(seed: Uint8Array, hash_function: HashFunction): Uint8Array;
};



const p521_curve: Curve = {
    name: 'P-521',
    public_key_length: 67,
    private_key_length: 66,
    curve: p521.CURVE,

    get_shared_point: (private_key: Uint8Array, public_key: Uint8Array) => {
        return p521.getSharedSecret(private_key, public_key, false);
    },

    get_public_key: (private_key: Uint8Array) => {
        return p521.getPublicKey(private_key);
    },

    valid_private_key: (private_key: Uint8Array) => {
        return p521.utils.isValidPrivateKey(private_key);
    },

    generate_secret: () => {
        return randomBytes(65);
    },
    
    from_seed: (seed: Uint8Array, hash_function: HashFunction) => {
        return hkdf(hash_function.get_func(), seed, undefined, 'P-521', 65);
    },

    get_shared_secret: (
        ephemeral_point: Uint8Array, 
        shared_point: Uint8Array,
        configuration: Configutaion
    ) => {
        const concated = concatBytes(ephemeral_point, shared_point);
        return derive_key(concated, configuration);
    }
};



const secp256k1_curve: Curve = {
    name: 'SECP256K1',
    public_key_length: 65,
    private_key_length: 32,
    curve: secp256k1.CURVE,

    get_shared_point: (private_key: Uint8Array, public_key: Uint8Array) => {
        return secp256k1.getSharedSecret(private_key, public_key);
    },

    get_public_key: (private_key: Uint8Array) => {
        return secp256k1.getPublicKey(private_key);
    },

    valid_private_key: (private_key: Uint8Array) => {
        return secp256k1.utils.isValidPrivateKey(private_key);
    },

    generate_secret: () => {
        return randomBytes(32);
    },
    
    from_seed: (seed: Uint8Array, hash_function: HashFunction) => {
        return hkdf(hash_function.get_func(), seed, undefined, 'SECP256K1', 32);
    },
    
    get_shared_secret: (
        ephemeral_point: Uint8Array, 
        shared_point: Uint8Array,
        configuration: Configutaion
    ) => {
        const concated = concatBytes(ephemeral_point, shared_point);
        return derive_key(concated, configuration);
    }
};



const supported_curves = {
    P521: p521_curve,
    SECP256K1: secp256k1_curve
};



export { 
    supported_curves, 
    Curve,
    
    p521_curve,
    secp256k1_curve
};