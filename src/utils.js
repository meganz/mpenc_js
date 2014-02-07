/**
 * @module utils
 * 
 * Some utilities.
 */

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

"use strict";

/**
 * Generates a new 256 bit random key, and converts it into a format that
 * the Curve25519 implementatino understands.
 * 
 * @returns
 *     16 bit word array of the key.
 * @private
 */
function _newKey256() {
    // TODO: Replace with Mega's implementation of rand(n)
    // https://github.com/meganz/webclient/blob/master/js/keygen.js#L21
    return c255lhexdecode(sjcl.codec.hex.fromBits(sjcl.random.randomWords(8, 6)));
}


/**
 * Clears the memory of a secret key array.
 * 
 * @param key
 *     The key to clear.
 * @private
 */
function _clearmem(key) {
    for (var i = 0; i < key.length; i++) {
        key[i] = 0;
    }
}


/**
 * Dumb array copy helper.
 * 
 * @param item
 *     The item for iterator.
 * @returns
 *     The item itself.
 * @private
 */
function _arrayCopy(item) {
    return item;
}


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
function _arrayIsSet(theArray) {
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
}


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
function _arrayIsSubSet(subset, superset) {
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
}


/**
 * Determines whether the list contains duplicates while excluding removed
 * elements (null).
 * 
 * @returns
 *     True for no duplicates in list.
 * @private
 */
function _noDuplicatesInList(aList) {
    var listCheck = [];
    for (var i = 0; i < aList.length; i++) {
        if (aList[i] !== null) {
            listCheck.push(aList[i]);
        }
    }
    return _arrayIsSet(listCheck);
}
