import { Configutaion } from '../configuration';
import PrivateKey from './private';



export default class PublicKey {
	private readonly _configuration: Configutaion;
    private readonly _public_key: Uint8Array;

    public constructor(
        data: Uint8Array,
        configuration: Configutaion,
    ) {
        this._configuration = configuration;
        this._public_key = data;

        // -- Ensure that the public key is valid length
        if (data.length !== configuration.elliptic_curve.public_key_length)
            throw new Error(`Invalid public key length: ${data.length}`); 
    }



    public get_shared_secret = (
        private_key: PrivateKey
    ): Uint8Array => this._configuration.elliptic_curve.get_shared_secret(
        this._public_key, 
        private_key.multiply(this.key),
        this._configuration
    );
    


    public toString = (): string => Buffer.from(this._public_key).toString('hex');
    public get key(): Uint8Array { return this._public_key; }
    public get configuration(): Configutaion { return this._configuration; }
}