import { Configutaion } from '../configuration';
import PublicKey from './public';



export default class PrivateKey {
    private readonly _configuration: Configutaion;
	private readonly _private_key: Uint8Array;
    private readonly _public_key: PublicKey;

    public constructor(
        configuration: Configutaion,
        private_key?: Uint8Array
    ) {
        this._configuration = configuration;

        // -- If a private key is provided, ensure it is the correct length
        if (private_key && private_key.length !== configuration.elliptic_curve.private_key_length)
            throw new Error(`Invalid private key length: ${private_key.length}`);

        // -- Set the private key and calculate the public key
        this._private_key = private_key || configuration.elliptic_curve.generate_secret();
        this._public_key = new PublicKey(this._calculate_public_key(), configuration);
    }



    public multiply = (
        key: Uint8Array
    ): Uint8Array => this._configuration.elliptic_curve.get_shared_point(
        this._private_key, key);

    private _calculate_public_key = (): Uint8Array =>
        this._configuration.elliptic_curve.get_public_key(this._private_key);

    public get_shared_secret = (
        public_key: Uint8Array
    ): Uint8Array => this._configuration.elliptic_curve.get_shared_secret(
        this._public_key.key, 
        this.multiply(public_key),
        this._configuration
    );



    public toString = (): string => Buffer.from(this._private_key).toString('hex');
    public get key(): Uint8Array { return this._private_key; }
    public get public_key(): PublicKey { return this._public_key; }
    public get configuration(): Configutaion { return this._configuration; }
}