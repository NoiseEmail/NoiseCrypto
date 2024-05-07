/**
 * @name buffer_to_string
 * @description Convert a buffer to a string
 * 
 * @param {Uint8Array} buffer - The buffer to convert
 * 
 * @returns {string} - The string representation of the buffer
 */
const buffer_to_string = (
    buffer: Uint8Array
): string => new TextDecoder().decode(buffer);



/**
 * @name buffer_to_hex
 * @description Convert a buffer to a hex string
 * ascii, so that it can be printed / stored
 * 
 * @param {Uint8Array} buffer - The buffer to convert'
 * 
 * @returns {string} - The hex string representation of the buffer
 */
const buffer_to_hex = (
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
const hex_to_buffer = (
    hex: string
): Uint8Array => Buffer.from(hex, 'hex');



/**
 * @name buffer_to_bigint
 * @description Convert a buffer to a BigInt
 * 
 * @param {Uint8Array} buffer - The buffer to convert
 * 
 * @returns {BigInt} - The BigInt representation of the buffer
 */
const buffer_to_bigint = (
    buffer: Uint8Array
): bigint => {
    let result = BigInt(0);
    for (let i = buffer.length - 1; i >= 0; i--) 
        result = result * BigInt(256) + BigInt(buffer[i]);
    return result;
}



/**
 * @name bigint_to_buffer
 * @description Convert a BigInt to a buffer
 * 
 * @param {BigInt} bigint - The BigInt to convert
 * 
 * @returns {Uint8Array} - The buffer representation of the BigInt
 */
const bigint_to_buffer = (
    bigint: bigint,
): Uint8Array => {
    const lenght = Math.ceil(Number(bigint).toString(16).length / 2);
    const result = new Uint8Array(lenght);

    for (let i = 0; i < lenght; i++) {
        result[i] = Number(bigint % BigInt(256));
        bigint = bigint / BigInt(256);
    }
    return result;
};



export {
    buffer_to_string,
    buffer_to_hex,
    hex_to_buffer,
    buffer_to_bigint,
    bigint_to_buffer
}