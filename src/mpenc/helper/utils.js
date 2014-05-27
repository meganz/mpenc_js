/**
 * @fileOverview
 * Some utilities.
 */

define([
    "asmcrypto",
    "ed25519",
], function(asmCrypto, ed25519) {
    "use strict";

    /**
     * @exports mpenc/helper/utils
     * Some utilities.
     *
     * @description
     * Some utilities.
     */
    var ns = {};

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

    ns._HEX_CHARS = '0123456789abcdef';

    /**
     * Generates a new random key as an array of 32 bit words.
     *
     * @param bits
     *     Number of bits of key strength (must be a multiple of 32).
     * @returns
     *     32 bit word array of the key.
     * @private
     */
    ns._newKey32 = function(bits) {
        var buffer = ns._newKey08(bits);
        var result = [];
        var value = 0;
        for (var i = 0; i < buffer.length; i += 4) {
            value = buffer[i];
            value += buffer[i + 1] << 8;
            value += buffer[i + 2] << 16;
            value += buffer[i + 3] << 24;
            result.push(value);
        }
        return result;
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
    ns._newKey16 = function(bits) {
        var buffer = ns._newKey08(bits);
        var result = [];
        var value = 0;
        for (var i = 0; i < buffer.length; i += 2) {
            value = buffer[i];
            value += buffer[i + 1] << 8;
            result.push(value);
        }
        return result;
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
    ns._newKey08 = function(bits) {
        var buffer = new Uint8Array(Math.floor(bits / 8));
        asmCrypto.getRandomValues(buffer);
        var result = [];
        for (var i = 0; i < buffer.length; i++) {
            result.push(buffer[i]);
        }
        return result;
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
    ns._key32to08 = function(key) {
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
    ns._key32to16 = function(key) {
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
     * Converts an 8-bit element (unsigned) array a hex string representation.
     *
     * @param key
     *     The key as an 8 bit (unsigned) integer array.
     * @returns
     *     Hex string representation of key (little endian).
     * @private
     */
    ns._key08toHex = function(key) {
        var out = '';
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            for (var j = 0; j < 2; j++) {
                out += ns._HEX_CHARS[value % 0x0f];
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
    ns._clearmem = function(key) {
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
    ns._arrayMaker = function(size, template) {
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
    ns._arrayIsSet = function(theArray) {
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
    ns._arrayIsSubSet = function(subset, superset) {
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
    ns._noDuplicatesInList = function(aList) {
        var listCheck = [];
        for (var i = 0; i < aList.length; i++) {
            if (aList[i] !== null) {
                listCheck.push(aList[i]);
            }
        }
        return ns._arrayIsSet(listCheck);
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
    ns.hex2bytearray = function(hexstring) {
        var result = [];
        var i = 0;
        while (i < hexstring.length) {
            result.push((ns._HEX_CHARS.indexOf(hexstring.charAt(i++)) << 4)
                        + ns._HEX_CHARS.indexOf(hexstring.charAt(i++)));
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
    ns.bytearray2hex = function(arr) {
        var result = '';
        for (var i = 0; i < arr.length; i++) {
            result += ns._HEX_CHARS.charAt(arr[i] >> 4)
                    + ns._HEX_CHARS.charAt(arr[i] & 15);
        }
        return result;
    };


    /**
     * Converts an 16-bit word element (unsigned) array a binary string representation.
     *
     * @param key
     *     The key as an 16-bit word element (unsigned) integer array.
     * @returns
     *     Binary string representation of key (big endian).
     * @private
     */
    ns.shortarray2bytestr = function(key) {
        var out = '';
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            var remainder = 0;
            for (var j = 0; j < 2; j++) {
                remainder = value % 256;
                out = String.fromCharCode(remainder) + out;
                value = value >> 8;
            }
        }
        return out;
    };


    /**
     * Converts a binary string to a 16-bit word element (unsigned) array representation.
     *
     * @param key
     *     Binary string representation of key (big endian).
     * @returns
     *     The key as an 16-bit word element (unsigned) integer array.
     * @private
     */
    ns.bytestr2shortarray = function(key) {
        var out = [];
        var i = 0;
        if (key.length % 2) {
            key = '\u0000' + key;
        }
        while (i < key.length) {
            out.unshift(key.charCodeAt(i) * 256 + key.charCodeAt(i + 1));
            i += 2;
        }
        return out;
    };


    /**
     * Returns a binary string representation of the SHA-256 hash function.
     *
     * @param data
     *     Data to hash.
     * @returns
     *     Binary string.
     */
    ns.sha256 = function(data) {
        return ed25519.bytes2string(asmCrypto.SHA256.bytes(data));
    };


    /**
     * Returns a binary string representation of the SHA-1 hash function.
     *
     * @param data
     *     Data to hash.
     * @returns
     *     Binary string.
     */
    ns.sha1 = function(data) {
        return ed25519.bytes2string(asmCrypto.SHA1.bytes(data));
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
    ns.clone = function(obj) {
        // Handle the 3 simple types, and null or undefined.
        if (null == obj || "object" != typeof obj) {
            return obj;
        }

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
                copy[i] = ns.clone(obj[i]);
            }
            return copy;
        }

        // Handle object.
        if (obj instanceof Object) {
            var copy = {};
            for (var attr in obj) {
                if (obj.hasOwnProperty(attr)) {
                    copy[attr] = ns.clone(obj[attr]);
                }
            }
            return copy;
        }

        throw new Error("Unable to copy obj! Its type isn't supported.");
    };


    /**
     * Constant time string comparison of two strings.
     *
     * @param str1 {string}
     *     The first string to be compared against the second.
     * @param str2 {string}
     *     The second string to be compared against the first.
     * @returns
     *     A true on equality.
     */
    ns.constTimeStringCmp = function(str1, str2) {
        // Compare lengths - can save a lot of time.
        if (str1.length !== str2.length) {
            return false;
        }

        var diff = 0;
        for (var i = 0, l = str1.length; i < l; i++) {
            diff |= (str1[i] ^ str2[i]);
        }
        return !diff;
    };


    /**
     * (Deep) compares two JavaScript arrays.
     *
     * See: http://stackoverflow.com/questions/7837456/comparing-two-arrays-in-javascript
     *
     * @param arr1
     *     The first array to be compared against the second.
     * @param arr2
     *     The second array to be compared against the first.
     * @returns
     *     A true on equality.
     */
    ns.arrayEqual = function(arr1, arr2) {
        // If the other array is a falsy value, return.
        if (!arr2) {
            return false;
        }

        // Compare lengths - can save a lot of time.
        if (arr1.length !== arr2.length) {
            return false;
        }

        for (var i = 0, l = arr1.length; i < l; i++) {
            // Check if we have nested arrays.
            if (arr1[i] instanceof Array && arr2[i] instanceof Array) {
                // Recurse into the nested arrays.
                if (!ns.arrayEqual(arr1[i], arr2[i])) {
                    return false;
                }
            } else if (arr1[i] !== arr2[i]) {
                // Warning - two different object instances will never be equal: {x:20} != {x:20}
                return false;
            }
        }
        return true;
    };


    /**
     * Check an object's invariants.
     *
     * Visits all ancestor prototypes of an object (including itself) and runs
     * the 1-ary functions listed in prototype.__invariants against the object.
     */
    ns.checkInvariants = function(obj) {
        var parent = obj;
        while (parent !== Object.prototype) {
            if (parent.hasOwnProperty("__invariants")) {
                var invariants = parent.__invariants
                for (var k in invariants) {
                    console.log("checking " + k + " on " + obj);
                    invariants[k](obj);
                }
            }
            parent = Object.getPrototypeOf(parent);
        }
    };


    /**
     * (Deep) compares two JavaScript objects.
     *
     * Note: May not work with some objects.
     *
     * See: http://stackoverflow.com/questions/7837456/comparing-two-arrays-in-javascript
     *
     * @param obj1
     *     The first object to be compared against the second.
     * @param obj1
     *     The second object to be compared against the first.
     * @returns
     *     A true on equality.
     */
    ns.objectEqual = function(obj1, obj2) {
        // For the first loop, we only check for types
        for (var propName in obj1) {
            // Check for inherited methods and properties - like .equals itself
            // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/hasOwnProperty
            // Return false if the return value is different.
            if (obj1.hasOwnProperty(propName) !== obj2.hasOwnProperty(propName)) {
                return false;
            }
            // Check instance type.
            else if (typeof obj1[propName] !== typeof obj2[propName]) {
                // Different types => not equal.
                return false;
            }
        }
        // Now a deeper check using other objects property names.
        for(var propName in obj2) {
            // We must check instances anyway, there may be a property that only exists in obj2.
            // I wonder, if remembering the checked values from the first loop would be faster or not .
            if (obj1.hasOwnProperty(propName) !== obj2.hasOwnProperty(propName)) {
                return false;
            } else if (typeof obj1[propName] !== typeof obj2[propName]) {
                return false;
            }

            // If the property is inherited, do not check any more (it must be equal if both objects inherit it).
            if(!obj1.hasOwnProperty(propName)) {
                continue;
            }

            // Now the detail check and recursion.

            // This returns the script back to the array comparing.
            if (obj1[propName] instanceof Array && obj2[propName] instanceof Array) {
                // Recurse into the nested arrays.
                if (!ns.arrayEqual(obj1[propName], obj2[propName])) {
                    return false;
                }
            } else if (obj1[propName] instanceof Object && obj2[propName] instanceof Object) {
                // Recurse into another objects.
                if (!ns.objectEqual(obj1[propName], obj2[propName])) {
                    return false;
                }
            }
            // Normal value comparison for strings and numbers.
            else if(obj1[propName] !== obj2[propName]) {
                return false;
            }
        }
        // If everything passed, let's say YES.
        return true;
    };

    return ns;
});
