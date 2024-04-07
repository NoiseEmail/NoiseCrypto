import { gcm, siv } from '@noble/ciphers/aes';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';


type SymEncFunction = {
    name: string;
    encrypt(
        data: Uint8Array, 
        key: Uint8Array,
    ): {
        data_length: number;
        nonce_length: number;
        data: Uint8Array;
        nonce: Uint8Array;
    };
    decrypt(
        data: Uint8Array, 
        key: Uint8Array, 
        nonce: Uint8Array,
    ): Uint8Array;
};



const gcm_aes: SymEncFunction = {
    name: 'AES-GCM',
    encrypt: (data: Uint8Array, key: Uint8Array) => {
        const nonce = randomBytes(12);
        const cipher = gcm(key, nonce);
        const encrypted = cipher.encrypt(data);

        return {
            data_length: data.length,
            nonce_length: nonce.length,
            data: encrypted,
            nonce: nonce,
        };
    },
    decrypt: (data: Uint8Array, key: Uint8Array, nonce: Uint8Array) => {
        const cipher = gcm(key, nonce);
        return cipher.decrypt(data);
    }
};



const supported_sym: Array<SymEncFunction> = [
    gcm_aes,
];



export {
    SymEncFunction,
    supported_sym,
    gcm_aes,
};