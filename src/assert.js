/**
 * @module assert
 * 
 * Assertion helper module.
 * 
 * Example usage:
 * 
 * <pre>
 * function lastElement(array) {
 *     assert(array.length > 0, "empty array in lastElement");
 *     return array[array.length - 1];
 * }
 * </pre>
 */

"use strict";

/**
 * Assertion exception.
 * @param message - Message for exception on failure.
 * @constructor
 */
function AssertionFailed(message) {
    this.message = message;
}
AssertionFailed.prototype = Object.create(Error.prototype);
AssertionFailed.prototype.name = 'AssertionFailed';


/**
 * Assert a given test condition.
 * 
 * Throws an AssertionFailed exception with the given `message` on failure.
 * 
 * @param test - Test statement.
 * @param message - Message for exception on failure.
 */
function assert(test, message) {
    if (!test) {
        throw new AssertionFailed(message);
    }
}

