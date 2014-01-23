/**
 * Some utils to help testing.
 */

"use strict";

/**
 * Array comparison function.
 * 
 * @param array1 - First array.
 * @param array2 - Second array.
 * @returns {Boolean} - True on content equality.
 */
function arrayCompare(array1, array2) {
    // Compare lengths - can save a lot of time.
    if (array1.length != array2.length)
        return false;

    for (var i = 0, l = array1.length; i < l; i++) {
        // Check if we have nested arrays
        if (array1[i] instanceof Array && array2[i] instanceof Array) {
            // Recurse into the nested arrays.
            if (!arrayCompare(array1[i], array2[i])) {
                return false;
            }
        } else if (array1[i] != array2[i]) {
            // Warning - two different object instances will never be equal: {x:20} != {x:20}
            return false;
        }
    }
    return true;
};

/**
 * Number of bits in a key.
 * @param key - The key to inspect.
 * @returns {Number} - Bits of the key.
 */
function keyBits(key) {
    return c255lhexencode(key).length * 4;
}
