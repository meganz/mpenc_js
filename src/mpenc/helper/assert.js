/**
 * @fileOverview
 * Assertion helper module.
 */

define([
    "megalogger",
], function(MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/helper/assert
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
    var ns = {};

    var logger = MegaLogger.getLogger('assert', undefined, 'helper');

    /**
     * Assertion exception.
     * @param message
     *     Message for exception on failure.
     * @constructor
     */
    ns.AssertionFailed = function(message) {
        this.message = message;
    };
    ns.AssertionFailed.prototype = Object.create(Error.prototype);
    ns.AssertionFailed.prototype.name = 'AssertionFailed';


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
    ns.assert = function(test, message) {
        if (!test) {
            logger.error(message);
            throw new ns.AssertionFailed(message);
        }
    };

    return ns;
});
