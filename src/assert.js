/**
 * @fileOverview
 * Assertion helper module.
 */

"use strict";

/**
 * @namespace
 * Assertion helper module.
 * 
 * @description
 * <p>Assertion helper module.</p>
 * 
 * <p>Example usage:</p>
 * 
 * <pre>
 * function lastElement(array) {
 *     _assert(array.length > 0, "empty array in lastElement");
 *     return array[array.length - 1];
 * }
 * </pre>
 */
mpenc.assert = {};

/**
 * Assertion exception.
 * @param message
 *     Message for exception on failure.
 * @constructor
 */
mpenc.assert.AssertionFailed = function(message) {
    this.message = message;
};
mpenc.assert.AssertionFailed.prototype = Object.create(Error.prototype);
mpenc.assert.AssertionFailed.prototype.name = 'AssertionFailed';


/**
 * Assert a given test condition.
 * 
 * Throws an `AssertionFailed` exception with the given `message` on failure.
 * 
 * @param test
 *     Test statement.
 * @param message
 *     Message for exception on failure.
 */
mpenc.assert.assert = function(test, message) {
    if (!test) {
        throw new mpenc.assert.AssertionFailed(message);
    }
};

var _assert = mpenc.assert.assert;
