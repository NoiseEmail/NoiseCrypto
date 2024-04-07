import { Configutaion } from "./configuration";



const encrypt = (
    data: Uint8Array,
    key: Uint8Array,
    configuration: Configutaion
) => configuration.symetric_function.encrypt(data, key);



const decrypt = (
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    configuration: Configutaion
) => configuration.symetric_function.decrypt(data, key, nonce);



export {
    encrypt,
    decrypt
};