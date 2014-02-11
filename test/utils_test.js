/**
 * @module utils_test
 *
 * Tests for utilities.
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

describe("module level", function() {
    var ns = mpenc.utils;

    describe('_arrayIsSubSet()', function() {
        it('check for sub/superset between arrays', function() {
            var subset = ['1', '2', '3'];
            var superset = ['0', '1', '2', '3', '4'];
            assert.ok(ns._arrayIsSubSet(subset, superset));
            assert.strictEqual(ns._arrayIsSubSet(superset, subset), false);
        });
    });
    
    describe('_arrayIsSet()', function() {
        it('check for non-duplicatoin of members in array', function() {
            var theArray = ['1', '2', '3'];
            assert.ok(ns._arrayIsSet(theArray));
            assert.strictEqual(ns._arrayIsSet(['2'].concat(theArray)), false);
        });
    });
});
