/**
 * @fileOverview
 * Tests for `mpenc/helper/patches` module.
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
    "curve255",
], function(ns, chai, curve255) {
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

        describe('(fromHex()/toHex())', function() {
            it('round trips', function() {
                var values = ['77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
                              '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
                              '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
                              'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
                              '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'];
                for (var i = 0; i < values.length; i++) {
                    var middle = curve255.fromHex(values[i]);
                    assert.strictEqual(curve255.toHex(middle), values[i]);
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

        describe('(toString()/fromString())', function() {
            it('round trips', function() {
                var values = [[11306, 7609, 64421, 45431, 39210, 60352, 12167, 57164, 26181, 20914, 49522, 15382, 42365, 29464, 27914, 30471],
                              [20074, 43675, 43406, 60324, 6900, 9784, 14861, 3519, 63322, 46142, 32220, 29835, 42836, 35120, 61449, 34080],
                              [57579, 65416, 35623, 7215, 46845, 9752, 45353, 28475, 3814, 33664, 32651, 31201, 35403, 25162, 2174, 23979],
                              [11087, 28552, 32276, 44540, 26445, 23416, 17352, 16259, 13623, 60644, 25026, 54107, 49588, 31613, 56189, 56990],
                              [5954, 7702, 39740, 30448, 40499, 18385, 8649, 57470, 3877, 32821, 15348, 29326, 11745, 42190, 40283, 19037]];
                for (var i = 0; i < values.length; i++) {
                    var middle = curve255.toString(values[i]);
                    assert.deepEqual(curve255.fromString(middle), values[i]);
                }
            });
        });
    });
});
