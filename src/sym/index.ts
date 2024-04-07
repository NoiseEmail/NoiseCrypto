import * as functions from './symetric';
import * as serialize from './serialize';



const encrypt = (
    func: functions.SymEncFunction,
    data: Uint8Array,
    key: Uint8Array,
): {
    data: Uint8Array;
    hex: string;
} => {
    const { data: encrypted, nonce } = func.encrypt(data, key);
    return serialize.serialize(encrypted, nonce, func);
};



const decrypt = (
    func: functions.SymEncFunction,
    enc_data: Uint8Array,
    key: Uint8Array,
): Uint8Array => {
    const { data, nonce, sym_func_name } = serialize.deserialize(enc_data);
    if (sym_func_name !== func.name) 
        throw new Error(`Invalid symetric function: ${sym_func_name}`);
    
    return func.decrypt(data, key, nonce);
};



export {
    functions,
    serialize,
    encrypt,
    decrypt,
};

