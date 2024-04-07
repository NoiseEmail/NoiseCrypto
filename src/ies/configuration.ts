import { concatBytes } from "@noble/hashes/utils";
import { ecc, symmetric, util } from "..";



type ConfigutaionOptions = {
	elliptic_curve: ecc.configuration.Configutaion;
    symetric_function: symmetric.functions.SymEncFunction;
};



class Configutaion {
    private readonly _elliptic_curve: ecc.configuration.Configutaion;
    private readonly _symetric_function: symmetric.functions.SymEncFunction;

    public constructor(
        configutaion: Partial<ConfigutaionOptions> = {}
    ) {
        const config = Object.assign(Configutaion.default_configuration(), configutaion);
        this._elliptic_curve = config.elliptic_curve;
        this._symetric_function = config.symetric_function;
    }



    public static default_configuration = (
    ): ConfigutaionOptions => { return {
        elliptic_curve: ecc.configuration.p521(),
        symetric_function: symmetric.functions.gcm_aes
    }};



    /**
     * @name key_pair
     * @description Create a pair of keys with this configuration pre-set
     * 
     * @returns {{
     *      private_key: ecc.PrivateKey, 
     *      public_key: ecc.PublicKey
     * }} - A pair of keys
     */
    public key_pair = (
    ): { 
        private_key: ecc.PrivateKey, 
        public_key: ecc.PublicKey 
    } => {
        const private_key = this._elliptic_curve.private_key();
        return {
            private_key,
            public_key: private_key.public_key
        };
    };



    /**
     * @name encrypt
     * @description Encrypt a message with this configuration
     * given a public key
     * 
     * @param {Uint8Array | string} message - The message to encrypt
     * @param {Uint8Array | string} public_key - The public key to encrypt with
     * 
     * @returns {Uint8Array} - The encrypted message
     */
    public encrypt = (
        message: Uint8Array | string,
        public_key: Uint8Array | string
    ): Uint8Array => {
        const public_key_bytes = typeof public_key === 'string' ? 
            new TextEncoder().encode(public_key) : 
            public_key;

        const data = typeof message === 'string' ? 
            new TextEncoder().encode(message) : 
            message;


        const shared = util.shared_secret.derive_encryption_key(
            public_key_bytes, 
            this._elliptic_curve
        );

        const encrypted = symmetric.encrypt(
            this._symetric_function, 
            data, 
            shared.shared_secret
        );

        // -- Append the ephemeral key to the encrypted data
        return concatBytes(
            shared.ephemeral_key, 
            encrypted.data
        );
    };



    /**
     * @name decrypt
     * @description Decrypt a message with this configuration
     * given a private key and an ephemeral key
     * 
     * @param {Uint8Array} encrypted - The encrypted message
     * @param {Uint8Array} private_key - The private key to decrypt with
     * 
     * @returns {Uint8Array} - The decrypted message
     */
    public decrypt = (
        encrypted: Uint8Array | string,
        private_key: Uint8Array | string
    ): Uint8Array => {
        if (typeof encrypted === 'string') encrypted = Configutaion.hex_to_buffer(encrypted);
        if (typeof private_key === 'string') private_key = Configutaion.hex_to_buffer(private_key);

        const ephemeral_key = encrypted.slice(0, this._elliptic_curve.elliptic_curve.public_key_length);
        const data = encrypted.slice(this._elliptic_curve.elliptic_curve.public_key_length);

        const shared = util.shared_secret.derive_decryption_key(
            private_key, 
            ephemeral_key, 
            this._elliptic_curve
        );

        return symmetric.decrypt(
            this._symetric_function, 
            data, 
            shared.shared_secret
        );
    };



    /**
     * @name buffer_to_string
     * @description Convert a buffer to a string
     * 
     * @param {Uint8Array} buffer - The buffer to convert
     * 
     * @returns {string} - The string representation of the buffer
     */
    public static buffer_to_string = (
        buffer: Uint8Array
    ): string => new TextDecoder().decode(buffer);



    /**
     * @name buffer_to_string
     * @description Convert a buffer to a hex string
     * ascii, so that it can be printed / stored
     * 
     * @param {Uint8Array} buffer - The buffer to convert'
     * 
     * @returns {string} - The hex string representation of the buffer
     */
    public static buffer_to_hex = (
        buffer: Uint8Array
    ): string => Buffer.from(buffer).toString('hex');



    /**
     * @name hex_to_buffer
     * @description Convert a hex string to a buffer
     * 
     * @param {string} hex - The hex string to convert
     * 
     * @returns {Uint8Array} - The buffer representation of the hex string
     */
    public static hex_to_buffer = (
        hex: string
    ): Uint8Array => Buffer.from(hex, 'hex');



    public get curve(): ecc.configuration.Configutaion { return this._elliptic_curve; }
    public get symetric_function(): symmetric.functions.SymEncFunction { return this._symetric_function; }
    public get hash_function(): util.hash.HashFunction { return this._elliptic_curve.hash_function; }

    public get ecc_configuration(): ecc.configuration.Configutaion { return this._elliptic_curve; }
    public get symetric_configuration(): symmetric.functions.SymEncFunction { return this._symetric_function; }
};



export {
    Configutaion,
    ConfigutaionOptions
};