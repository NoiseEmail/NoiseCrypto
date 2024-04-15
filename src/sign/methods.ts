import { p521 } from '@noble/curves/p521';



type SignMethod = {
    name: string;
    sign(data: Uint8Array, private_key: Uint8Array): {
        data: Uint8Array;
        toString(): string;
    };
    verify(data: Uint8Array | string, signature: Uint8Array, public_key: Uint8Array): boolean;
};



const p521_sign: SignMethod = {
    name: 'P-521',
    sign: (data: Uint8Array, private_key: Uint8Array) => {
        const signature = p521.sign(data, private_key);
        return {
            data: signature.toDERRawBytes(),
            toString: () => signature.toDERHex()
        };
    },
    verify: (data: Uint8Array | string, signature: Uint8Array, public_key: Uint8Array) => {
        return p521.verify(signature, data, public_key);
    }
};



const supported_sign_methods = {
    p521: p521_sign
};



export {
    SignMethod,
    supported_sign_methods,

    p521_sign
}