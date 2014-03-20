/**
 * @fileOverview
 * Test of the `mpenc.codec` module.
 */

/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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
    var ns = mpenc.codec;
    
    var UPFLOW_MESSAGE = atob('AQAAATEBAQABMgECAAEAAQMAATEBAwABMgEDAAEzAQMAATQ'
                              + 'BAwABNQEDAAE2AQQAAAEEACBqmYo4w/GJ7VtkY2BRKhOV'
                              + 'fE2H35PtNLM7Xxh+oVEJTQEFACBqmYo4w/GJ7VtkY2BRK'
                              + 'hOVfE2H35PtNLM7Xxh+oVEJTQEGACBy9+FIdgh3VJNQmM'
                              + 'rGKbacscnvP643kDddVolnQYWT5QEHAAA=');
    
    describe("module level TLV stuff", function() {
        describe("_short2bin()", function() {
            it('just convert', function() {
                var values = [0, 42, 1234, 21356];
                var expected = ['\u0000\u0000', '\u0000\u002a', '\u0004\u00d2', 'Sl'];
                for (var i = 0; i < values.length; i++) {
                    assert.strictEqual(ns._short2bin(values[i]), expected[i]);
                }
            });
        });
        
        describe("_bin2short()", function() {
            it('just convert', function() {
                var values = ['\u0000\u0000', '\u0000\u002a', '\u0004\u00d2', 'Sl'];
                var expected = [0, 42, 1234, 21356];
                for (var i = 0; i < values.length; i++) {
                    assert.strictEqual(ns._bin2short(values[i]), expected[i]);
                }
            });
        });
        
        describe("encodeTLV()", function() {
            it('null equivalent', function() {
                assert.strictEqual(ns.encodeTLV(0, ''), '\u0000\u0000\u0000\u0000');
            });
            
            it('some examples', function() {
                var tests = [[0, 'hello'],
                             [42, "Don't panic!"],
                             [21356, _td.SESSION_ID],
                             [14, null]];
                var expected = ['\u0000\u0000\u0000\u0005hello',
                                "\u0000\u002a\u0000\u000cDon't panic!",
                                'Sl\u0000\u0020' + _td.SESSION_ID,
                                '\u0000\u000e\u0000\u0000'];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.encodeTLV(tests[i][0], tests[i][1]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });
        
        describe("_encodeTlvArray()", function() {
            it('null equivalents', function() {
                var tests = [[], [''], [null], null];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns._encodeTlvArray(0, tests[i]);
                    assert.strictEqual(result, '\u0000\u0000\u0000\u0000');
                }
            });
            
            it('passed in non-array', function() {
                assert.throws(function() { ns._encodeTlvArray(0, '42'); },
                              'Value passed neither an array or null.');
            });
            
            it('some examples', function() {
                var result = ns._encodeTlvArray(42, ['1', '22', '333']);
                assert.strictEqual(result,
                                     '\u0000\u002a\u0000\u00011'
                                   + '\u0000\u002a\u0000\u000222'
                                   + '\u0000\u002a\u0000\u0003333');
            });
        });
        
        describe("decodeTLV()", function() {
            it('null equivalent', function() {
                var result = ns.decodeTLV('\u0000\u0000\u0000\u0000');
                assert.strictEqual(result.type, 0);
                assert.strictEqual(result.value, null);
            });
            
            it('some examples', function() {
                var tests = ['\u0000\u0000\u0000\u0005hello',
                             "\u0000\u002a\u0000\u000cDon't panic!",
                             'Sl\u0000\u0020' + _td.SESSION_ID,
                             '\u0000\u0000\u0000\u0005hello\u0000\u0000\u0000\u0005world'];
                var expected = [[0, 'hello', ''],
                                [42, "Don't panic!", ''],
                                [21356, _td.SESSION_ID, ''],
                                [0, 'hello', '\u0000\u0000\u0000\u0005world']];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.decodeTLV(tests[i]);
                    assert.strictEqual(result.type, expected[i][0]);
                    assert.strictEqual(result.value, expected[i][1]);
                    assert.strictEqual(result.rest, expected[i][2]);
                }
            });
            
            it('misformed TLV', function() {
                assert.throws(function() { ns.decodeTLV('\u0000\u0000\u0000\u0005hell'); },
                              'TLV payload length does not match indicated length.');
            });
        });
        
        describe("encodeMessage()", function() {
            it('upflow message', function() {
                var message = {
                    source: '1',
                    dest: '2',
                    agreement: 'initial',
                    flow: 'upflow',
                    members: ['1', '2', '3', '4', '5', '6'],
                    intKeys: [null, curve255.toString(_td.C25519_PUB_KEY)],
                    nonces: [curve255.toString(_td.C25519_PUB_KEY)],
                    pubKeys: [djbec.bytes2string(_td.ED25519_PUB_KEY)],
                    sessionSignature: null
                };
                var encodeTlvStub = sinon.stub(mpenc.codec, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
                mpenc.codec.encodeTLV = encodeTlvStub;
                var result = ns.encodeMessage(message);
                mpenc.codec.encodeTLV.restore();
                assert.lengthOf(result, 56);
            });
            
            it('upflow message binary', function() {
                var message = {
                    source: '1',
                    dest: '2',
                    agreement: 'initial',
                    flow: 'upflow',
                    members: ['1', '2', '3', '4', '5', '6'],
                    intKeys: [null, curve255.toString(_td.C25519_PUB_KEY)],
                    nonces: [curve255.toString(_td.C25519_PUB_KEY)],
                    pubKeys: [djbec.bytes2string(_td.ED25519_PUB_KEY)],
                    sessionSignature: null
                };
                var result = ns.encodeMessage(message);
                assert.strictEqual(result, UPFLOW_MESSAGE);
            });
        });
        
        describe("decodeMessage()", function() {
            it('upflow message', function() {
                var expected = {
                    source: '1',
                    dest: '2',
                    agreement: 'initial',
                    flow: 'upflow',
                    members: ['1', '2', '3', '4', '5', '6'],
                    intKeys: [null, curve255.toString(_td.C25519_PUB_KEY)],
                    nonces: [curve255.toString(_td.C25519_PUB_KEY)],
                    pubKeys: [djbec.bytes2string(_td.ED25519_PUB_KEY)],
                    sessionSignature: null
                };
                var result = ns.decodeMessage(UPFLOW_MESSAGE);
                assert.strictEqual(result.source, expected.source);
                assert.strictEqual(result.dest, expected.dest);
                assert.strictEqual(result.agreement, expected.agreement);
                assert.strictEqual(result.flow, expected.flow);
                assert.deepEqual(result.members, expected.members);
                assert.deepEqual(result.intKeys, expected.intKeys);
                assert.deepEqual(result.nonces, expected.nonces);
                assert.deepEqual(result.pubKeys, expected.pubKeys);
                assert.strictEqual(result.sessionSignature, expected.sessionSignature);
            });
        });
    });
})();
