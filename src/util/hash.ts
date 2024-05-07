import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { CHash } from '@noble/curves/abstract/utils';



type HashFunction = {
    name: string;
    output_lenght: number;
    get_func: () => CHash;
    hash(data: string | Uint8Array): {
        toString(encoding: 'hex'): string;
        unit8Array(): Uint8Array;
    };
};



const sha256_hash: HashFunction = {
    get_func: () => sha256,
    name: 'SHA-256',
    output_lenght: 256,
    hash: (data: string | Uint8Array) => {
        const hash = sha256.create();
        hash.update(data);
        const digest = hash.digest();

        return {
            toString(encoding: 'hex') {
                return Buffer.from(digest).toString(encoding);
            },
            
            unit8Array() {
                return digest;
            }
        }
    }
};



const sha512_hash: HashFunction = {
    name: 'SHA-512',
    output_lenght: 512,
    get_func: () => sha512,
    hash: (data: string | Uint8Array) => {
        const hash = sha512.create();
        hash.update(data);
        const digest = hash.digest();

        return {
            toString(encoding: 'hex') {
                return Buffer.from(digest).toString(encoding);
            },
            
            unit8Array() {
                return digest;
            }
        }
    }
};



const supported_hashes = {
    SHA256: sha256_hash,
    SHA512: sha512_hash
};



export {
    HashFunction,

    sha256_hash,
    sha512_hash,
    supported_hashes
};