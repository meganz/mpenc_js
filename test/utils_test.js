/**
 * @fileOverview
 * Tests for `mpenc.utils` module.
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

(function() {
    "use strict";
    
    var assert = chai.assert;

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
        
        describe('_newKey32()', function() {
            it('properly sized keys', function() {
                var keySizes = [128, 256, 512];
                for (var i = 0; i < keySizes.length; i++) {
                    var newKey = ns._newKey32(keySizes[i]);
                    assert.strictEqual(_tu.keyBits(newKey), keySizes[i]);
                }
            });
        });
        
        describe('_newKey16()', function() {
            it('properly sized keys', function() {
                var keySizes = [128, 256, 512];
                for (var i = 0; i < keySizes.length; i++) {
                    var newKey = ns._newKey16(keySizes[i]);
                    assert.strictEqual(_tu.keyBits(newKey, 16), keySizes[i]);
                }
            });
        });
        
        describe('_newKey08()', function() {
            it('properly sized keys', function() {
                var keySizes = [128, 256, 512];
                for (var i = 0; i < keySizes.length; i++) {
                    var newKey = ns._newKey08(keySizes[i]);
                    assert.strictEqual(_tu.keyBits(newKey, 8), keySizes[i]);
                }
            });
        });
        
        describe('hex2bytearray()', function() {
            it('simple conversion test', function() {
                var values = ['477579', '61339391d56552dad72495a71a47b0f11ba3ebaf'];
                var expected = [[71, 117, 121],
                                [97, 51, 147, 145, 213, 101, 82, 218, 215, 36,
                                 149, 167, 26, 71, 176, 241, 27, 163, 235, 175]];
                for (var i = 0; i < values.length; i++) {
                    var result = ns.hex2bytearray(values[i]);
                    assert.deepEqual(result, expected[i]);
                }
            });
        });
    });
    
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
})();