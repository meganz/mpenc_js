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


/**
 * (Deep) compares two JavaScript objects.
 * Will try to ignore methods/functions on objects.
 *
 * Note: May not work with some objects.
 *
 * @param obj1
 *     First object to compare.
 * @param obj2
 *     Second object to compare.
 * @returns
 *     `true` on object equality.
 */
_tu.deepCompare = function(obj1, obj2) {
    // Handle array.
    if (obj1 instanceof Array) {
        for (var i = 0, len = obj1.length; i < len; i++) {
            if (obj1[i] !== obj2[i]) {
                return false;
            }
        }
        return true;
    }

    // Handle object.
    if (obj1 instanceof Object) {
        for (var attr in Object.keys(obj1)) {
            if (obj1[attr] !== obj2[attr]) {
                return false;
            }
            if ((obj1[attr] instanceof Object)
                    && (Object.keys(obj1[attr]).length > 0)) {
                return _tu.deepCompare(obj1[attr], obj2[attr]);
            }
        }
        return true;
    }

    throw new Error("Unable to compare objects! Its types aren't supported.");
};