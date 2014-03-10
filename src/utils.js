/**
 * @fileOverview
 * Some utilities.
 */

(function() {
    "use strict";

    /**
     * @namespace
     * Some utilities.
     * 
     * @description
     * Some utilities.
     */
    mpenc.utils = {};
    
    /*
     * Created: 7 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
     *
     * (c) 2014 by Mega Limited, Wellsford, New Zealand
     *     http://mega.co.nz/
     *
     * This file is part of the multi-party chat encryption suite.
     *
     * This code is free software: you can redistribute it and/or modify
     * it under the terms of the GNU Affero General Public License version 3
     * as published by the Free Software Foundation. See the accompanying
     * LICENSE file or <https://www.gnu.org/licenses/> if it is unavailable.
     * 
     * This code is distributed in the hope that it will be useful,
     * but WITHOUT ANY WARRANTY; without even the implied warranty of
     * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
     */
    
    mpenc.utils._HEX_CHARS = '0123456789abcdef';
    
    /**
     * Generates a new random key as an array of 32 bit words.
     * 
     * @param bits
     *     Number of bits of key strength (must be a multiple of 32).
     * @returns
     *     32 bit word array of the key.
     * @private
     */
    mpenc.utils._newKey32 = function(bits) {
        // TODO: Replace with Mega's implementation of rand(n)
        // https://github.com/meganz/webclient/blob/master/js/keygen.js#L21
        var paranoia = [0,48,64,96,128,192,256,384,512,768,1024].indexOf(bits);
        return sjcl.random.randomWords(Math.floor(bits / 32), paranoia);
    };
    
    
    /**
     * Generates a new random key, and converts it into a format that
     * the Curve25519 implementation understands.
     * 
     * @param bits
     *     Number of bits of key strength (must be a multiple of 32).
     * @returns
     *     16 bit word array of the key.
     * @private
     */
    mpenc.utils._newKey16 = function(bits) {
        return mpenc.utils._key32to16(mpenc.utils._newKey32(bits));
    };
    
    
    /**
     * Generates a new random key, and converts it into a format that
     * the Ed25519 implementation understands.
     * 
     * @param bits
     *     Number of bits of key strength (must be a multiple of 32).
     * @returns
     *     8 bit value array of the key.
     * @private
     */
    mpenc.utils._newKey08 = function(bits) {
        return mpenc.utils._key32to08(mpenc.utils._newKey32(bits));
    };
    
    
    /**
     * Converts a key representation to an array with 8 bit chunks.
     * 
     * @param key
     *     The key as a 32 bit word array.
     * @returns
     *     8 bit value array of the key.
     * @private
     */
    mpenc.utils._key32to08 = function(key) {
        var keyOut = [];
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            for (var j = 0; j < 4; j++) {
                keyOut.push(value % 0xff & 0xff);
                value = value >> 8;
            }
        }
        return keyOut;
    };
    
    
    /**
     * Converts a key representation to an array with 16 bit chunks.
     * 
     * @param key
     *     The key as a 32 bit word array.
     * @returns
     *     16 bit value array of the key.
     * @private
     */
    mpenc.utils._key32to16 = function(key) {
        var keyOut = [];
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            for (var j = 0; j < 2; j++) {
                keyOut.push(value % 0xffff & 0xffff);
                value = value >> 16;
            }
        }
        return keyOut;
    };
    
    
    /**
     * Converts a key representation to an array with 16 bit chunks.
     * 
     * @param key
     *     The key as a 32 bit word array.
     * @returns
     *     16 bit value array of the key.
     * @private
     */
    mpenc.utils._key08toHex = function(key) {
        var out = '';
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            for (var j = 0; j < 2; j++) {
                out += c255lhexchars[value % 0x0f];
                value = value >> 4;
            }
        }
        return out;
    };
    
    
    /**
     * Clears the memory of a secret key array.
     * 
     * @param key
     *     The key to clear.
     * @private
     */
    mpenc.utils._clearmem = function(key) {
        for (var i = 0; i < key.length; i++) {
            key[i] = 0;
        }
    };
    
    
    /**
     * Dumb array maker/initialiser helper.
     * 
     * @param size
     *     Size of new array.
     * @param template
     *     Default value to initialise every element with.
     * @returns
     *     The new array.
     * @private
     */
    mpenc.utils._arrayMaker = function(size, template) {
        var arr = new Array(size);
        for (var i = 0; i < size; i++) {
            arr[i] = template;
        }
        return arr;
    };
    
    
    /**
     * Checks for unique occurrence of all elements within the array.
     * 
     * Note: Array members must be directly comparable for equality
     * (g. g. numbers or strings).
     * 
     * @param theArray
     *     Array under scrutiny.
     * @returns
     *     True for uniqueness.
     * @private
     */
    mpenc.utils._arrayIsSet = function(theArray) {
        // Until ES6 is down everywhere to offer the Set() class, we need to work
        // around it.
        var mockSet = {};
        var item;
        for (var i = 0; i < theArray.length; i++) {
            item = theArray[i];
            if (item in mockSet) {
                return false;
            } else {
                mockSet[item] = true;
            }
        }
        return true;
    };
    
    
    /**
     * Checks whether one array's elements are a subset of another.
     * 
     * Note: Array members must be directly comparable for equality
     * (g. g. numbers or strings).
     * 
     * @param subset
     *     Array to be checked for being a subset.
     * @param superset
     *     Array to be checked for being a superset.
     * @returns
     *     True for the first being a subset of the second.
     * @private
     */
    mpenc.utils._arrayIsSubSet = function(subset, superset) {
        // Until ES6 is down everywhere to offer the Set() class, we need to work
        // around it.
        var mockSet = {};
        var item;
        for (var i = 0; i < superset.length; i++) {
            item = superset[i];
            if (item in mockSet) {
                return false;
            } else {
                mockSet[item] = true;
            }
        }
        for (var i = 0; i < subset.length; i++) {
            if (!(subset[i] in mockSet)) {
                return false;
            }
        }
        return true;
    };
    
    
    /**
     * Determines whether the list contains duplicates while excluding removed
     * elements (null).
     * 
     * @param aList
     *     The list to check for duplicates.
     * @returns
     *     True for no duplicates in list.
     * @private
     */
    mpenc.utils._noDuplicatesInList = function(aList) {
        var listCheck = [];
        for (var i = 0; i < aList.length; i++) {
            if (aList[i] !== null) {
                listCheck.push(aList[i]);
            }
        }
        return mpenc.utils._arrayIsSet(listCheck);
    };
    
    
    /**
     * Converts a hex string to a a byte array (array of Uint8, retains endianness).
     * 
     * Note: No sanity or error checks are performed.
     * 
     * @param hexstring
     *     Hexadecimal string.
     * @returns
     *     Array of byte values (unsigned integers).
     */
    mpenc.utils.hex2bytearray = function(hexstring) {
        var result = [];
        var i = 0;
        while (i < hexstring.length) {
            result.push((mpenc.utils._HEX_CHARS.indexOf(hexstring.charAt(i++)) << 4)
                        + mpenc.utils._HEX_CHARS.indexOf(hexstring.charAt(i++)));
        }
        return result;
    };
    
    /**
     * Converts a byte array to a hex string (array of Uint8, retains endianness).
     * 
     * Note: No sanity or error checks are performed.
     * 
     * @param arr
     *     Array of byte values (unsigned integers).
     * @returns
     *     Hexadecimal string.
     */
    mpenc.utils.bytearray2hex = function(arr) {
        var result = '';
        for (var i = 0; i < arr.length; i++) {
            result += CHARS.charAt(arr[i] >> 4)
                    + mpenc.utils._HEX_CHARS.charAt(arr[i] & 15);
        }
        return result;
    };
    
    /**
     * (Deep) clones a JavaScript object.
     * 
     * Note: May not work with some objects.
     * 
     * See: http://stackoverflow.com/questions/728360/most-elegant-way-to-clone-a-javascript-object
     * 
     * @param obj
     *     The object to be cloned.
     * @returns
     *     A deep copy of the original object.
     */
    mpenc.utils.clone = function(obj) {
        // Handle the 3 simple types, and null or undefined.
        if (null == obj || "object" != typeof obj) return obj;
    
        // Handle date.
        if (obj instanceof Date) {
            var copy = new Date();
            copy.setTime(obj.getTime());
            return copy;
        }
    
        // Handle array.
        if (obj instanceof Array) {
            var copy = [];
            for (var i = 0, len = obj.length; i < len; i++) {
                copy[i] = mpenc.utils.clone(obj[i]);
            }
            return copy;
        }
    
        // Handle object.
        if (obj instanceof Object) {
            var copy = {};
            for (var attr in obj) {
                if (obj.hasOwnProperty(attr)) {
                    copy[attr] = mpenc.utils.clone(obj[attr]);
                }
            }
            return copy;
        }
    
        throw new Error("Unable to copy obj! Its type isn't supported.");
    };
})();
