import { hkdf } from "@noble/hashes/hkdf";
import { Configutaion } from "../ecc/configuration";
import { PublicKey } from "../ecc";



const derive_key = (
    data: Uint8Array,
    configuration: Configutaion,
): Uint8Array => hkdf(
    configuration.hash_function.get_func(), 
    data, 
    undefined, 
    undefined,
    configuration.derived_key_size
);



const derive_encryption_key = (
    raw_public_key: Uint8Array,
    configuration: Configutaion,
): {
    configuration: Configutaion;
    shared_secret: Uint8Array;
    ephemeral_key: Uint8Array;
} => {
    // -- Generate an ephemeral private key
    const ephemeral_private_key = configuration.private_key();
    const public_key = configuration.public_key(raw_public_key);

    return {
        shared_secret: ephemeral_private_key.get_shared_secret(public_key.key),
        ephemeral_key: ephemeral_private_key.public_key.key,
        configuration
    }
};



const derive_decryption_key = (
    raw_private_key: Uint8Array,
    ephemeral_key: Uint8Array,
    configuration: Configutaion,
): {
    configuration: Configutaion;
    shared_secret: Uint8Array;
} => {
    const private_key = configuration.private_key(raw_private_key);
    const key_size = configuration.elliptic_curve.public_key_length;
    const sender_key = new PublicKey(
        ephemeral_key.subarray(0, key_size), 
        configuration
    );


    return {
        shared_secret: sender_key.get_shared_secret(private_key),
        configuration
    }
};



export {
    derive_key,
    derive_encryption_key,
    derive_decryption_key
};