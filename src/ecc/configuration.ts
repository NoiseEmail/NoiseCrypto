import { HashFunction, supported_hashes } from "../util/hash";
import { Curve, supported_curves } from "./curves";
import PrivateKey from "./keys/private";
import PublicKey from "./keys/public";



type ConfigutaionOptions = {
	elliptic_curve: Curve;
    hash_function: HashFunction;
	derived_key_size: number;
};



class Configutaion {
	private readonly _elliptic_curve: Curve;
	private readonly _derived_key_size: number;
    private readonly _hash_function: HashFunction;


	public constructor(
		configutaion: Partial<ConfigutaionOptions>
	) {
		const config = Object.assign(Configutaion.default_configuration(), configutaion);
		this._elliptic_curve = config.elliptic_curve;
		this._derived_key_size = config.derived_key_size;
        this._hash_function = config.hash_function;
	}



	public static default_configuration = (
	): ConfigutaionOptions => { return {
		elliptic_curve: supported_curves.P521,
		derived_key_size: 32,
        hash_function: supported_hashes.SHA512
	}};




	/**
	 * @name private_key
	 * @description Create a new instance of PrivateKey with this 
	 * configuration pre-set
	 * 
	 * @param {Uint8Array} [private_key=undefined] - The private key value [optional]
	 * 
	 * @returns {PrivateKey} - A new instance of PrivateKey
	 */
	public private_key = (
		private_key?: Uint8Array
	): PrivateKey => new PrivateKey(this, private_key);



    /**
     * @name public_key
     * @description Create a new instance of PublicKey with this
     * configuration pre-set given a `public_key` value
     * 
     * @param {Uint8Array} public_key - The public key value
     * 
     * @returns {PublicKey} - A new instance of PublicKey
     */
    public public_key = (
        public_key: Uint8Array
    ): PublicKey => new PublicKey(public_key, this);
	


	public serialize = () => {
		return {
            hash_function: this._hash_function.name,
			elliptic_curve: {
                name: this.elliptic_curve.name,
                public_key_length: this.elliptic_curve.public_key_length,
                private_key_length: this.elliptic_curve.private_key_length
            },
			derived_key_size: this.derived_key_size
		};
	};



    public hash = (data: string) => this._hash_function.hash(data);

	public static p521 = (): Configutaion => new Configutaion({ elliptic_curve: supported_curves.P521 });
	public static x25519 = (): Configutaion => new Configutaion({ elliptic_curve: supported_curves.X25519 });
	public static secp256k1 = (): Configutaion => new Configutaion({ elliptic_curve: supported_curves.SECP256K1 });

	public get elliptic_curve(): Curve { return this._elliptic_curve; }
    public get hash_function(): HashFunction { return this._hash_function; }
	public get derived_key_size(): number { return this._derived_key_size; }
};



const p521 = Configutaion.p521;
const x25519 = Configutaion.x25519;
const secp256k1 = Configutaion.secp256k1;



export {
	ConfigutaionOptions,
	Configutaion,

	p521,
    x25519,
	secp256k1
};