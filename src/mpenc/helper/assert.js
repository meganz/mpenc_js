/*
 * Created: 23 Jan 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2015 by Mega Limited, Auckland, New Zealand
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

define([
    "megalogger",
], function(MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/helper/assert
     * @private
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
     * @private
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
