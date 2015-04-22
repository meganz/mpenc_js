/**
 * @fileOverview
 * Test of the `mpenc/codec` module.
 */

/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/message",
    "mpenc/version",
    "mpenc/helper/utils",
    "jodid25519",
    "asmcrypto",
    "megalogger",
    "chai",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, version, utils, jodid25519, asmCrypto, MegaLogger,
            chai, sinon_sandbox) {
    "use strict";

    var assert = chai.assert;

    // set test data
    _td.DATA_MESSAGE_CONTENT.protocol = version.PROTOCOL_VERSION;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    function _dummySessionKeyStore() {
        var sessionKeyStore = { sessionIDs: [_td.SESSION_ID],
                                sessions: {} };
        sessionKeyStore.sessions[_td.SESSION_ID] = {
            sid: _td.SESSION_ID,
            members: ['Moe', 'Larry', 'Curly'],
            groupKeys: [_td.GROUP_KEY]
        };
        return sessionKeyStore;
    }

    describe("MessageSecurity.encrypt()", function() {
        it('data message', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            var result = new ns.MessageSecurity(_td.ED25519_PRIV_KEY,
                                                _td.ED25519_PUB_KEY,
                                                sessionKeyStore).encrypt('foo');
            // 4 TLVs with 109 bytes:
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 2), IV (4 + 12), encr. message (4 + 5)
            assert.lengthOf(atob(result.slice(7, -1)), 109);
        });

        it('data message with second group key', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            sessionKeyStore.sessionIDs.push('foo');
            sessionKeyStore.sessions['foo'] = {};
            sessionKeyStore.sessions[_td.SESSION_ID].groupKeys.push('foo');
            var result = new ns.MessageSecurity(_td.ED25519_PRIV_KEY,
                                                _td.ED25519_PUB_KEY,
                                                sessionKeyStore).encrypt('foo');
            // 4 TLVs with 109 bytes:
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 2), IV (4 + 12), encr. message (4 + 5)
            assert.lengthOf(atob(result.slice(7, -1)), 109);
        });

        it('data message with exponential padding', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            var result = new ns.MessageSecurity(_td.ED25519_PRIV_KEY,
                                                _td.ED25519_PUB_KEY,
                                                sessionKeyStore).encrypt('foo', 32);
            // 4 TLVs with 136 bytes:
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 2), IV (4 + 12), encr. message (4 + 32)
            assert.lengthOf(atob(result.slice(7, -1)), 136);
        });
    });

    describe("MessageSecurity.decrypt()", function() {
        it('data message', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            sessionKeyStore.pubKeyMap = {'Moe': _td.ED25519_PUB_KEY };
            var result = new ns.MessageSecurity(null, null, sessionKeyStore).decrypt(
                    { from: 'Moe', message: _td.DATA_MESSAGE_STRING });

            assert.strictEqual(result.from, 'Moe');
            assert.strictEqual(result.message, _td.DATA_MESSAGE_CONTENT.data);
        });

        it('data message with second group key', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            sessionKeyStore.sessionIDs.push('foo');
            sessionKeyStore.sessions['foo'] = {};
            sessionKeyStore.sessions[_td.SESSION_ID].groupKeys.push('foo');
            sessionKeyStore.pubKeyMap = {'Moe': _td.ED25519_PUB_KEY };
            var result = new ns.MessageSecurity(null, null, sessionKeyStore).decrypt(
                    { from: 'Moe', message: _td.DATA_MESSAGE_STRING2 });

            assert.strictEqual(result.from, 'Moe');
            assert.strictEqual(result.message, _td.DATA_MESSAGE_CONTENT.data);
        });

        it('data message, debug on', function() {
            sandbox.stub(MegaLogger._logRegistry.codec, '_log');
            sandbox.stub(MegaLogger._logRegistry.message, '_log');

            var sessionKeyStore = _dummySessionKeyStore();
            sessionKeyStore.sessionIDs.push('foo');
            sessionKeyStore.sessions['foo'] = {};
            sessionKeyStore.sessions[_td.SESSION_ID].groupKeys.push('foo');
            sessionKeyStore.pubKeyMap = {'Moe': _td.ED25519_PUB_KEY };

            var result = new ns.MessageSecurity(null, null, sessionKeyStore).decrypt(
                    { from: 'Moe', message: _td.DATA_MESSAGE_STRING });

            var log = MegaLogger._logRegistry.codec._log.getCall(0).args;
            assert.deepEqual(log, [0, ['mpENC decoded message debug: ',
                                       ['sidkeyHint: 0x54',
                                        'messageSignature: aLW0Axx5p0RVPvjoX0rug6m3VhqsGmX17MTd1eSqdUBaCqwqAO2JfxGNM0p5xoPoQFltrdCGIRvK/QxskpTHBw==',
                                        'protocol: 1',
                                        'messageType: 0x0 (PARTICIPANT_DATA)',
                                        'messageIV: qq36/fToW+Z7I7b5',
                                        'rawDataMessage: aU6y8g8=']]]);
            log = MegaLogger._logRegistry.message._log.getCall(0).args;
            assert.deepEqual(log, [0, ['mpENC decrypted data message debug: ',
                                       'foo']]);
        });

        it('data message with exponential padding', function() {
            var sessionKeyStore = _dummySessionKeyStore();
            sessionKeyStore.pubKeyMap = {'Moe': _td.ED25519_PUB_KEY };

            var result = new ns.MessageSecurity(null, null, sessionKeyStore).decrypt(
                    { from: 'Moe', message: _td.DATA_MESSAGE_STRING32 });

            assert.strictEqual(result.from, 'Moe');
            assert.strictEqual(result.message, _td.DATA_MESSAGE_CONTENT.data);
        });
    });

    describe("_encryptDataMessage()", function() {
        it('null equivalents', function() {
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns._encryptDataMessage(tests[i], key), null);
            }
        });

        it('data messages', function() {
            var iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['6H0=',
                            '6H/R1g==',
                            '6HGhi6z7+lgyR6wtKss=',
                            '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2Lo=',
                            '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJA==',
                            '6HexIFGySvliTa0h',
                            '6G2tJ2ay/R0uBuRkDphJAkEV',
                            '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0'];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns._encryptDataMessage(tests[i], key);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });

        it('data messages with exponential padding', function() {
            var iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var paddingSize = 32;
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['6H3l5MLcjnhCJsJESeosdiR5GYxDe7o4vcjZLeE2R88=',
                            '6H/R1sLcjnhCJsJESeosdiR5GYxDe7o4vcjZLeE2R88=',
                            '6HGhi6z7+lgyR6wtKsssdiR5GYxDe7o4vcjZLeE2R88=',
                            '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2LrZLeE2R88=',
                            '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJBw1J7RY12A4WCdDMg==',
                            '6HexIFGySvliTa0hSeosdiR5GYxDe7o4vcjZLeE2R88=',
                            '6G2tJ2ay/R0uBuRkDphJAkEVGYxDe7o4vcjZLeE2R88=',
                            '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0R88='];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns._encryptDataMessage(tests[i], key, paddingSize);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(result.data.length % paddingSize, 0);
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });

        it('data messages explicitly without padding', function() {
            var iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var paddingSize = 0;
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['6H0=',
                            '6H/R1g==',
                            '6HGhi6z7+lgyR6wtKss=',
                            '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2Lo=',
                            '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJA==',
                            '6HexIFGySvliTa0h',
                            '6G2tJ2ay/R0uBuRkDphJAkEV',
                            '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0'];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns._encryptDataMessage(tests[i], key, paddingSize);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });
    });

    describe("_decryptDataMessage()", function() {
        it('null equivalents', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns._decryptDataMessage(tests[i], key, iv), null);
            }
        });

        it('data messages', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['6H0=',
                         '6H/R1g==',
                         '6HGhi6z7+lgyR6wtKss=',
                         '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2Lo=',
                         '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJA==',
                         '6HexIFGySvliTa0h',
                         '6G2tJ2ay/R0uBuRkDphJAkEV',
                         '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0'];
            var expected = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                            "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                            'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            for (var i = 0; i < tests.length; i++) {
                var result = ns._decryptDataMessage(atob(tests[i]), key, iv);
                assert.strictEqual(result, expected[i]);
            }
        });

        it('data messages with exponential padding', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['6H3l5MLcjnhCJsJESeosdiR5GYxDe7o4vcjZLeE2R88=',
                         '6H/R1sLcjnhCJsJESeosdiR5GYxDe7o4vcjZLeE2R88=',
                         '6HGhi6z7+lgyR6wtKsssdiR5GYxDe7o4vcjZLeE2R88=',
                         '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2LrZLeE2R88=',
                         '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJBw1J7RY12A4WCdDMg==',
                         '6HexIFGySvliTa0hSeosdiR5GYxDe7o4vcjZLeE2R88=',
                         '6G2tJ2ay/R0uBuRkDphJAkEVGYxDe7o4vcjZLeE2R88=',
                         '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0R88='];
            var expected = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                            "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                            'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            for (var i = 0; i < tests.length; i++) {
                var result = ns._decryptDataMessage(atob(tests[i]), key, iv);
                assert.strictEqual(result, expected[i]);
            }
        });
    });

    describe("_encryptDataMessage()/_decryptDataMessage()", function() {
        it('several round trips', function() {
            for (var i = 0; i < 5; i++) {
                var key = jodid25519.utils.bytes2string(utils._newKey08(128));
                var messageLength = Math.floor(256 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var encryptResult = ns._encryptDataMessage(message, key);
                var cipher = encryptResult.data;
                var iv = encryptResult.iv;
                var clear = ns._decryptDataMessage(cipher, key, iv);
                assert.strictEqual(message, clear);
            }
        });
    });

});
