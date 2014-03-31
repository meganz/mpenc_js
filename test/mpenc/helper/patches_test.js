/**
 * @fileOverview
 * Tests for `mpenc.util.patches` module.
 */

/*
 * Created: 20 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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

define([
    "mpenc/helper/patches",
    "chai",
], function(ns, chai) {
    "use strict";

    var assert = chai.assert;

    describe("curve255 patches", function() {
        describe('(toHex())', function() {
            it('simple conversion test', function() {
                var values = [[722, 18838], [123], [123, 0], []];
                var expected = ['499602d2', '007b', '0000007b', ''];
                for (var i = 0; i < values.length; i++) {
                    var result = curve255.toHex(values[i]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });

        describe('(fromHex())', function() {
            it('simple conversion test', function() {
                var values = ['499602d2', '007b', '0000007b', '000007b', '00007b', ''];
                var expected = [[722, 18838], [123], [123, 0], [123, 0], [123, 0], []];
                for (var i = 0; i < values.length; i++) {
                    var result = curve255.fromHex(values[i]);
                    assert.deepEqual(result, expected[i]);
                }
            });
        });

        describe('(toString())', function() {
            it('simple conversion test', function() {
                var values = [[29556, 26209, 29300, 25185, 29801, 24946, 21356],
                              [25187, 97], []];
                var expected = ['Slartibartfast', '\u0000abc', ''];
                for (var i = 0; i < values.length; i++) {
                    var result = curve255.toString(values[i]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });

        describe('(fromString())', function() {
            it('simple conversion test', function() {
                var values = ['Slartibartfast', '\u0000abc', 'abc', ''];
                var expected = [[29556, 26209, 29300, 25185, 29801, 24946, 21356],
                                [25187, 97], [25187, 97], []];
                for (var i = 0; i < values.length; i++) {
                    var result = curve255.fromString(values[i]);
                    assert.deepEqual(result, expected[i]);
                }
            });
        });
    });
});
