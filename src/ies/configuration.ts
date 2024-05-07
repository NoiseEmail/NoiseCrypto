import { concatBytes, randomBytes } from "@noble/hashes/utils";
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
        if (typeof encrypted === 'string') encrypted = util.convert.hex_to_buffer(encrypted);
        if (typeof private_key === 'string') private_key = util.convert.hex_to_buffer(private_key);

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
     * @name derive_key 
     * @description Derive a key from input data
     * 
     * @param {Uint8Array | string} data - The data to derive the key from
     * 
     * @returns {Uint8Array} - The derived key in accordance with the configuration
     */
    public derive_key = (
        data: Uint8Array | string
    ): Uint8Array => {
        // -- Convert the data to bytes
        let bytes = typeof data === 'string' ? 
            new TextEncoder().encode(data) : 
            data;

        // -- Check if the data is the correct lenght for the curve
        if (bytes.length !== this._elliptic_curve.elliptic_curve.private_key_length)
            bytes = this.from_seed(bytes);

        // -- Derive the key
        return bytes;
    };



    /**
     * @name hash
     * @description Hash a message with this configuration
     * 
     * @param {Uint8Array | string} message - The message to hash
     * 
     * @returns {Uint8Array} - The hash of the message
     */
    public hash = (
        message: Uint8Array | string
    ): Uint8Array => {
        const data = typeof message === 'string' ? 
            new TextEncoder().encode(message) : 
            message;

        return this._elliptic_curve.hash_function.get_func()(data);
    };



    /**
     * @name from_seed
     * @description Derive a key from a seed, regardless of the length
     * 
     * @param {Uint8Array | string} seed - The seed to derive the key from
     * 
     * @returns {Uint8Array} - The derived key in accordance with the configuration
     */
    public from_seed = (
        seed: Uint8Array | string
    ): Uint8Array => {
        // -- Convert the seed to bytes
        const bytes = typeof seed === 'string' ? 
            new TextEncoder().encode(seed) : 
            seed;

        // -- Derive the key
        const key = this._elliptic_curve.elliptic_curve.from_seed(
            bytes, 
            this._elliptic_curve.hash_function
        );

        if (key.length !== this._elliptic_curve.elliptic_curve.private_key_length)
            throw new Error(`Invalid seed length: ${key.length}`);

        return key;
    };



    /**
     * @name random_hash
     * @description Generates a random hash
     * 
     * @returns {Uint8Array} - The random hash in bytes
     */
    public random_hash = (
    ): Uint8Array => {
        const random_bytes = randomBytes(this._elliptic_curve.hash_function.output_lenght);
        return this._elliptic_curve.hash(random_bytes).unit8Array();
    }



    /**
     * @name get_public_key
     * @description Get the public key from a private key
     * 
     * @param {Uint8Array} private_key - The private key to get the public key from
     * 
     * @returns {Uint8Array} - The public key
     */
    public get_public_key = (
        private_key: Uint8Array
    ): Uint8Array => this._elliptic_curve.elliptic_curve.get_public_key(private_key);



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