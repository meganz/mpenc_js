/**
 * @fileOverview
 * Some utils to help testing.
 */

"use strict";

var _tu = {};

/**
 * Number of bits in a key.
 * 
 * @param key
 *     The key to inspect.
 * @param wordSize
 *     Number of bits per word.
 * @returns {Number}
 *     Bits of the key.
 */
_tu.keyBits = function(key, wordSize) {
    wordSize = wordSize || 32;
    return key.length * wordSize;
};


/**
 * Number of bits in a key.
 * 
 * @param key
 *     The key to inspect.
 * @param wordSize
 *     Number of bits per word.
 * @returns {Number}
 *     Bits of the key.
 */
_tu.keyBits = function(key, wordSize) {
    wordSize = wordSize || 32;
    return key.length * wordSize;
};


/**
 * Returns a random byte string of given length.
 * 
 * It does not use cryptographic strong random numbers!
 * 
 * @param length
 *     Length of binary string.
 * @returns {string}
 *     Resulging random binary string.
 */
_tu.cheapRandomString = function(length) {
    var out = '';
    for (var i = 0; i < length; i++) {
        out += String.fromCharCode(Math.floor(0xff * Math.random()));
    }
    return out;
};
