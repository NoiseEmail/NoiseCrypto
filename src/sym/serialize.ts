import { SymEncFunction } from "./symetric";


const serialize = (
    data: Uint8Array,
    nonce: Uint8Array,
    sym_func: SymEncFunction,
): {
    data: Uint8Array;
    hex: string;
} => {
    
    // -- The first bytes are always going to be metadata
    //    therefore we can safely assume that the delimiter
    //    is not from the data
    //    data_length.nonc_length.sym_func_name.data.nonce
    const data_hex = Buffer.from(data).toString('hex');
    const nonce_hex = Buffer.from(nonce).toString('hex');

    const formated = [
        data_hex.length.toString(16),
        '.',
        nonce_hex.length.toString(16),
        '.',
        sym_func.name,
        '.',
        data_hex,
        '.',
        nonce_hex,
    ].join('');
    

    return {
        data: Buffer.from(formated),
        hex: formated,
    };
};



const deserialize = (
    data: Uint8Array | string,
): {
    data_length: number;
    nonce_length: number;
    data: Uint8Array;
    nonce: Uint8Array;
    sym_func_name: string;
} => {
    const data_str = typeof data === 'string' ? 
        data : 
        Buffer.from(data).toString('utf8');

    const parts = data_str.split('.');
    const data_length = parseInt(parts[0], 16);
    const nonce_length = parseInt(parts[1], 16);
    const sym_func_name = parts[2];
    const data_hex = parts[3];
    const nonce_hex = parts[4];

    // -- Validate lenghts
    if (data_hex.length !== data_length) 
        throw new Error('Invalid data length');

    if (nonce_hex.length !== nonce_length)
        throw new Error('Invalid nonce length');
    
    return {
        data_length,
        nonce_length,
        data: Buffer.from(data_hex, 'hex'),
        nonce: Buffer.from(nonce_hex, 'hex'),
        sym_func_name,
    };
}



export {
    serialize,
    deserialize,
};