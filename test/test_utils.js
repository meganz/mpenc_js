/**
 * @fileOverview
 * Some utils to help testing.
 */

"use strict";

var _tu = {};

/**
 * Number of bits in a key.
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
