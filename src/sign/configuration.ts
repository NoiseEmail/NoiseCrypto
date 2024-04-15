import { methods } from './';



type ConfigutaionOptions = {
	sign_method: methods.SignMethod;
};



class Configutaion {
    private readonly _sign_method: methods.SignMethod;

    public constructor(
        configutaion: Partial<ConfigutaionOptions> = {}
    ) {
        const config = Object.assign(Configutaion.default_configuration(), configutaion);
        this._sign_method = config.sign_method;
    }



    public static default_configuration = (
    ): ConfigutaionOptions => { return {
        sign_method: methods.p521_sign
    }};



    /**
     * @name sign
     * @description Sign a message with this configuration
     * 
     * @param {Uint8Array} data - The data to sign
     * @param {Uint8Array} private_key - The private key to sign with
     * 
     * @returns {{
     *     data: Uint8Array,
     *     toString(): string
     * }} - The signature
     */
    public sign = (
        data: Uint8Array,
        private_key: Uint8Array
    ): {
        data: Uint8Array,
        toString(): string
    } => this._sign_method.sign(data, private_key);



    /**
     * @name verify
     * @description Verify a signature with this configuration
     * 
     * @param {Uint8Array | string} data - The data to verify
     * @param {Uint8Array} signature - The signature to verify
     * @param {Uint8Array} public_key - The public key to verify with
     * 
     * @returns {boolean} - True if the signature is valid
     */
    public verify = (
        data: Uint8Array | string,
        signature: Uint8Array,
        public_key: Uint8Array
    ): boolean => this._sign_method.verify(data, signature, public_key);
    
};



export {
    Configutaion,
    ConfigutaionOptions
};