/**
 * @fileOverview
 * Test of the `mpenc/codec` module.
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

define([
    "mpenc/codec",
    "mpenc/version",
    "mpenc/helper/utils",
    "mpenc/debug",
    "jodid25519",
    "asmcrypto",
    "chai",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, version, utils, debug, jodid25519, asmCrypto, chai, sinon_sandbox, sinon_assert) {
    "use strict";

    var assert = chai.assert;

    // Shut up warning messages on random number generation for unit tests.
    asmCrypto.random.skipSystemRNGWarning = true;

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
                var tests = ['', null, undefined];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.encodeTLV(0, tests[i]);
                    assert.strictEqual(result, '\u0000\u0000\u0000\u0000');
                }
                assert.strictEqual(ns.encodeTLV(0), '\u0000\u0000\u0000\u0000');
            });

            it('some examples', function() {
                var tests = [[0, 'hello'],
                             [42, "Don't panic!"],
                             [21356, _td.SESSION_ID],
                             [14, ''],
                             [14, null],
                             [1, '\u0001']];
                var expected = ['\u0000\u0000\u0000\u0005hello',
                                "\u0000\u002a\u0000\u000cDon't panic!",
                                'Sl\u0000\u0020' + _td.SESSION_ID,
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u0001\u0000\u0001\u0001'];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.encodeTLV(tests[i][0], tests[i][1]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });

        describe("_encodeTlvArray()", function() {
            it('null content equivalents', function() {
                var tests = [[''], [null]];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns._encodeTlvArray(0, tests[i]);
                    assert.strictEqual(result, '\u0000\u0000\u0000\u0000');
                }
            });

            it('null equivalents', function() {
                var tests = [[], null];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns._encodeTlvArray(0, tests[i]);
                    assert.strictEqual(result, '');
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
                assert.strictEqual(result.value, '');
            });

            it('some examples', function() {
                var tests = ['\u0000\u0000\u0000\u0005hello',
                             "\u0000\u002a\u0000\u000cDon't panic!",
                             'Sl\u0000\u0020' + _td.SESSION_ID,
                             '\u0000\u000e\u0000\u0000***',
                             '\u0000\u0000\u0000\u0005hello\u0000\u0000\u0000\u0005world'];
                var expected = [[0, 'hello', ''],
                                [42, "Don't panic!", ''],
                                [21356, _td.SESSION_ID, ''],
                                [14, '', '***'],
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

        describe("isDataContent()", function() {
            it('empty content', function() {
                var tests = [null, undefined, ''];
                for (var i = 0; i < tests.length; i++) {
                    assert.notOk(ns.isDataContent(tests[i]));
                }
            });

            it('greet message', function() {
                assert.notOk(ns.isDataContent(_td.DOWNFLOW_MESSAGE_STRING));
            });

            it('data message', function() {
                assert.ok(ns.isDataContent(_td.DATA_MESSAGE_STRING));
            });
        });

        describe("categoriseMessage()", function() {
            it('normal categories', function() {
                var tests = ['Klaatu barada nikto.',
                             '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?foo.',
                             _td.DOWNFLOW_MESSAGE_PAYLOAD,
                             _td.DATA_MESSAGE_PAYLOAD,
                             '?mpENC Error:foo.'];
                var expected = [[ns.MESSAGE_CATEGORY.PLAIN, 'Klaatu barada nikto.'],
                                [ns.MESSAGE_CATEGORY.MPENC_QUERY, version.PROTOCOL_VERSION],
                                [ns.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE, _td.DOWNFLOW_MESSAGE_STRING],
                                [ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE, _td.DATA_MESSAGE_STRING],
                                [ns.MESSAGE_CATEGORY.MPENC_ERROR, 'foo.']];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.categoriseMessage(tests[i]);
                    assert.strictEqual(result.category, expected[i][0]);
                    assert.strictEqual(result.content, expected[i][1]);
                }
            });

            it('unknown message', function() {
                assert.throws(function() { ns.categoriseMessage('?mpENC...blah.'); },
                              'Unknown mpENC message.');
            });

            it('null message', function() {
                var tests = [null, undefined, ''];
                for (var i = 0; i < tests.length; i++) {
                    assert.strictEqual(ns.categoriseMessage(tests[i]), null);
                }
            });
        });

        describe("encodeMessageContent()", function() {
            it('upflow message', function() {
                sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
                var result = ns.encodeMessageContent(_td.UPFLOW_MESSAGE_CONTENT,
                                                     null,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result, 60);
            });

            it('upflow message binary', function() {
                var result = ns.encodeMessageContent(_td.UPFLOW_MESSAGE_CONTENT,
                                                     null,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result, _td.UPFLOW_MESSAGE_STRING);
            });

            it('downflow message for quit', function() {
                sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
                var result = ns.encodeMessageContent(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                     null,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result, 24);
            });

            it('downflow message for quit binary', function() {
                var result = ns.encodeMessageContent(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                     null,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result, _td.DOWNFLOW_MESSAGE_STRING);
            });

            it('data message', function() {
                var result = ns.encodeMessageContent('foo', _td.GROUP_KEY,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                // 4 TLVs with 113 bytes:
                // signature (4 + 64), protocol v (4 + 1), IV (4 + 16), encr. message (4 + 16)
                assert.lengthOf(result, 113);
            });

            it('data message with exponential padding', function() {
                var result = ns.encodeMessageContent('foo', _td.GROUP_KEY,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY, 32);
                // 4 TLVs with 113 bytes:
                // signature (4 + 64), protocol v (4 + 1), IV (4 + 16), encr. message (4 + 32)
                assert.lengthOf(result, 129);
            });
        });

        describe("decodeMessageContent()", function() {
            it('upflow message', function() {
                var result = ns.decodeMessageContent(_td.UPFLOW_MESSAGE_STRING,
                                                     null,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result.source, _td.UPFLOW_MESSAGE_CONTENT.source);
                assert.strictEqual(result.dest, _td.UPFLOW_MESSAGE_CONTENT.dest);
                assert.strictEqual(result.agreement, _td.UPFLOW_MESSAGE_CONTENT.agreement);
                assert.strictEqual(result.flow, _td.UPFLOW_MESSAGE_CONTENT.flow);
                assert.deepEqual(result.members, _td.UPFLOW_MESSAGE_CONTENT.members);
                assert.deepEqual(result.intKeys, _td.UPFLOW_MESSAGE_CONTENT.intKeys);
                assert.deepEqual(result.nonces, _td.UPFLOW_MESSAGE_CONTENT.nonces);
                assert.deepEqual(result.pubKeys, _td.UPFLOW_MESSAGE_CONTENT.pubKeys);
                assert.strictEqual(result.sessionSignature, _td.UPFLOW_MESSAGE_CONTENT.sessionSignature);
            });

            it('upflow message, debug on', function() {
                sandbox.stub(window.console, 'log');
                sandbox.stub(debug, 'decoder', true);
                ns.decodeMessageContent(_td.UPFLOW_MESSAGE_STRING,
                                        null, _td.ED25519_PUB_KEY);
                var log = console.log.args[0][0];
                assert.deepEqual(log, ['messageSignature: 6VxiIOX5U7jH7Sz67+dEIflnD48O0p4x1VIkjL3v6V3wf7z8iR4DGdZ8tujq7HkHtpLBuX8w87zaXN6Nv/WEDg==',
                                       'protocol: 1',
                                       'from: 1', 'to: 2 (upflow)',
                                       'agreement: initial',
                                       'member: 1', 'member: 2', 'member: 3', 'member: 4', 'member: 5', 'member: 6',
                                       'intKey: ', 'intKey: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                       'nonce: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                       'pubKey: 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=']);

            });

            it('downflow message for quit', function() {
                var result = ns.decodeMessageContent(_td.DOWNFLOW_MESSAGE_STRING,
                                                     null,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result.source, _td.DOWNFLOW_MESSAGE_CONTENT.source);
                assert.strictEqual(result.dest, _td.DOWNFLOW_MESSAGE_CONTENT.dest);
                assert.strictEqual(result.agreement, 'auxiliary');
                assert.strictEqual(result.flow, _td.DOWNFLOW_MESSAGE_CONTENT.flow);
                assert.strictEqual(result.signingKey, _td.DOWNFLOW_MESSAGE_CONTENT.signingKey);
            });

            it('wrong protocol version', function() {
                var message = _td.UPFLOW_MESSAGE_STRING.substring(68, 72)
                            + String.fromCharCode(77)
                            + _td.UPFLOW_MESSAGE_STRING.substring(73);
                assert.throws(function() { ns.decodeMessageContent(message, null,
                                                                   _td.ED25519_PUB_KEY); },
                              'Received wrong protocol version: 77');
            });

            it('data message', function() {
                var result = ns.decodeMessageContent(_td.DATA_MESSAGE_STRING,
                                                     _td.GROUP_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result.signature, 64);
                assert.strictEqual(result.signatureOk, _td.DATA_MESSAGE_CONTENT.signatureOk);
                assert.strictEqual(result.protocol, _td.DATA_MESSAGE_CONTENT.protocol);
                assert.lengthOf(result.iv, 16);
                assert.strictEqual(result.data, _td.DATA_MESSAGE_CONTENT.data);
            });

            it('data message, debug on', function() {
                sandbox.stub(window.console, 'log');
                sandbox.stub(debug, 'decoder', true);
                ns.decodeMessageContent(_td.DATA_MESSAGE_STRING,
                                        _td.GROUP_KEY, _td.ED25519_PUB_KEY);

                var log = console.log.args[0][0];
                assert.deepEqual(log, ['messageSignature: 0Et9tlUIl6SnWWRRF337BqWZvIao/BH4KU7qZeVB3QnL7ls+zfBVl5O3RxsZjibfMdjOsuCu6CsuFCb7mFQsBA==',
                                       'protocol: 1',
                                       'messageIV: i4vUqwamDTYp9T1rm4osZg==',
                                       'rawDataMessage: hy2I5zmItNhJ7S9+QWB6eg==',
                                       'decryptDataMessage: foo']);
            });

            it('data message with exponential padding', function() {
                var result = ns.decodeMessageContent(_td.DATA_MESSAGE_STRING32,
                                                     _td.GROUP_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result.signature, 64);
                assert.strictEqual(result.signatureOk, _td.DATA_MESSAGE_CONTENT.signatureOk);
                assert.strictEqual(result.protocol, _td.DATA_MESSAGE_CONTENT.protocol);
                assert.lengthOf(result.iv, 16);
                assert.strictEqual(result.data, _td.DATA_MESSAGE_CONTENT.data);
            });

            it('data message, invalid signature', function() {
                // Change a single byte.
                var message = _td.DATA_MESSAGE_STRING.substring(0, 10)
                            + String.fromCharCode(77)
                            + _td.DATA_MESSAGE_STRING.substring(11);
                assert.throws(function() { ns.decodeMessageContent(message,
                                                                   _td.GROUP_KEY,
                                                                   _td.ED25519_PUB_KEY); },
                              'Signature of message does not verify');
            });
        });

        describe("inspectMessageContent()", function() {
            it('upflow message', function() {
                var result = ns.inspectMessageContent(_td.UPFLOW_MESSAGE_STRING);
                assert.deepEqual(result, {protocol: 1, from: '1', to: '2',
                                          origin: null, type: null,
                                          greet: {agreement: 'initial', flow: 'upflow',
                                                  negotiation: null, fromInitiator: null,
                                                  members: ['1', '2', '3', '4', '5', '6'],
                                                  numNonces: 1, numIntKeys: 2, numPubKeys: 1}});
            });

            it('downflow message for quit', function() {
                var result = ns.inspectMessageContent(_td.DOWNFLOW_MESSAGE_STRING);
                assert.deepEqual(result, {protocol: 1, from: '1', to: '',
                                          origin: null, type: null,
                                          greet: {agreement: 'auxiliary', flow: 'downflow',
                                                  negotiation: null, fromInitiator: null,
                                                  members: [],
                                                  numNonces: 0, numIntKeys: 0, numPubKeys: 0}});
            });
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
                intKeys: [null, _td.C25519_PUB_KEY],
                nonces: [_td.C25519_PUB_KEY],
                pubKeys: [_td.ED25519_PUB_KEY],
                sessionSignature: null
            };
            sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeMessage(message, null, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY);
            assert.strictEqual(result, '?mpENC:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.');
        });

        it('upflow message binary', function() {
            var message = {
                source: '1',
                dest: '2',
                agreement: 'initial',
                flow: 'upflow',
                members: ['1', '2', '3', '4', '5', '6'],
                intKeys: [null, _td.C25519_PUB_KEY],
                nonces: [_td.C25519_PUB_KEY],
                pubKeys: [_td.ED25519_PUB_KEY],
                sessionSignature: null
            };
            var result = ns.encodeMessage(message, null, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY);
            assert.strictEqual(result, _td.UPFLOW_MESSAGE_PAYLOAD);
        });

        it('downflow message on quit', function() {
            var message = _td.DOWNFLOW_MESSAGE_CONTENT;
            sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeMessage(message, null, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY);
            assert.strictEqual(result, '?mpENC:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.');
        });

        it('downflow message on quit binary', function() {
            var result = ns.encodeMessage(_td.DOWNFLOW_MESSAGE_CONTENT,
                                          null, _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY);
            assert.strictEqual(result, _td.DOWNFLOW_MESSAGE_PAYLOAD);
        });

        it('null message', function() {
            assert.strictEqual(ns.encodeMessage(null, null,
                                                _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY),
                               null);
            assert.strictEqual(ns.encodeMessage(undefined, null,
                                                _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY),
                               null);
        });

        it('data message', function() {
            var message = 'wha tekau ma rua';
            sandbox.stub(ns, 'encodeMessageContent').returns('42');
            var groupKey = _td.COMP_KEY.substring(0, 16);
            var result = ns.encodeMessage(message, groupKey, _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY);
            sinon_assert.calledOnce(ns.encodeMessageContent);
            assert.lengthOf(ns.encodeMessageContent.getCall(0).args, 5);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[0],
                               message);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[1],
                               groupKey);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[2],
                               _td.ED25519_PRIV_KEY);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[3],
                               _td.ED25519_PUB_KEY);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[4], 0);
            assert.strictEqual(result, '?mpENC:NDI=.');
        });

        it('data message with exponential padding', function() {
            var message = 'wha tekau ma rua';
            sandbox.stub(ns, 'encodeMessageContent').returns('42');
            var groupKey = _td.COMP_KEY.substring(0, 16);
            var result = ns.encodeMessage(message, groupKey, _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, 32);
            sinon_assert.calledOnce(ns.encodeMessageContent);
            assert.lengthOf(ns.encodeMessageContent.getCall(0).args, 5);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[0],
                               message);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[1],
                               groupKey);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[2],
                               _td.ED25519_PRIV_KEY);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[3],
                               _td.ED25519_PUB_KEY);
            assert.strictEqual(ns.encodeMessageContent.getCall(0).args[4], 32);
            assert.strictEqual(result, '?mpENC:NDI=.');
        });
    });

    describe("encryptDataMessage()", function() {
        it('null equivalents', function() {
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.encryptDataMessage(tests[i], key), null);
            }
        });

        it('data messages', function() {
            var iv = asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f');
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['VuuhjX/Tv+izxDqav8aZkw==',
                            '+DY4ThyAs+EDFQZGSK1BWQ==',
                            'LCXI34/Fou4+aewRq+WSIw==',
                            'QyfKqgn9g0A6LZDpjLTupIJz9I4WfkHPDgRu3VYVipY=',
                            'VtT8MtqFepiSohOU2RiikNw75ts+DzWmzM5n9NOwPRrlFQ1xxTCP5eVzFNt+ZBCpNzH2u9ZfXZJYysgADgQLNg==',
                            'SC5vp2Ml4w7vcnT/gHgTbA==',
                            'vXWdTN0pKmL9W7TRZN4nfcy0fmXk1lSWr5JFbzg+yeA=',
                            'gsou4Ncoykbkg4NHm19CMSUISmfi8eCVHWM0E9yxDaw='];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.encryptDataMessage(tests[i], key);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });

        it('data messages with exponential padding', function() {
            var iv = asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f');
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var paddingSize = 32;
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['6XKTgeuvwFtdRmFP7IaF4rSVaXJMqW8OETTe9B9AZwY=',
                            'M5HrNJxP+snqy6OuVNQvYAe6SSvZaAF0Kef3eysHGU4=',
                            'tMj2YWriiLT1pzthGVly/oBScpN7XraZ2byXvJTfA98=',
                            'QyfKqgn9g0A6LZDpjLTupLwnw0UYldJyHx2uOOMhNVI=',
                            'VtT8MtqFepiSohOU2RiikNw75ts+DzWmzM5n9NOwPRrlFQ1xxTCP5eVzFNt+ZBCpmYJojdVrVsIM714z8QsI5g==',
                            'NrTBK7A3vRIpKuN9SMw8uMPFUXuznTB+/nSx4MFJ2do=',
                            'vXWdTN0pKmL9W7TRZN4nfcZkoAAlGcuRJpdupKe34wk=',
                            'gsou4Ncoykbkg4NHm19CMUNzO0YA/BEwAzNqdCJxkbc='];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.encryptDataMessage(tests[i], key, paddingSize);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(result.data.length % paddingSize, 0);
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });

        it('data messages explicitly without padding', function() {
            var iv = asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f');
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var paddingSize = 0;
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['VuuhjX/Tv+izxDqav8aZkw==',
                            '+DY4ThyAs+EDFQZGSK1BWQ==',
                            'LCXI34/Fou4+aewRq+WSIw==',
                            'QyfKqgn9g0A6LZDpjLTupIJz9I4WfkHPDgRu3VYVipY=',
                            'VtT8MtqFepiSohOU2RiikNw75ts+DzWmzM5n9NOwPRrlFQ1xxTCP5eVzFNt+ZBCpNzH2u9ZfXZJYysgADgQLNg==',
                            'SC5vp2Ml4w7vcnT/gHgTbA==',
                            'vXWdTN0pKmL9W7TRZN4nfcy0fmXk1lSWr5JFbzg+yeA=',
                            'gsou4Ncoykbkg4NHm19CMSUISmfi8eCVHWM0E9yxDaw='];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.encryptDataMessage(tests[i], key, paddingSize);
                assert.strictEqual(result.iv, jodid25519.utils.bytes2string(iv));
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });
    });

    describe("decryptDataMessage()", function() {
        it('null equivalents', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.decryptDataMessage(tests[i], key, iv), null);
            }
        });

        it('data messages', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['VuuhjX/Tv+izxDqav8aZkw==',
                         '+DY4ThyAs+EDFQZGSK1BWQ==',
                         'LCXI34/Fou4+aewRq+WSIw==',
                         'QyfKqgn9g0A6LZDpjLTupIJz9I4WfkHPDgRu3VYVipY=',
                         'VtT8MtqFepiSohOU2RiikNw75ts+DzWmzM5n9NOwPRrlFQ1xxTCP5eVzFNt+ZBCpNzH2u9ZfXZJYysgADgQLNg==',
                         'SC5vp2Ml4w7vcnT/gHgTbA==',
                         'vXWdTN0pKmL9W7TRZN4nfcy0fmXk1lSWr5JFbzg+yeA=',
                         'gsou4Ncoykbkg4NHm19CMSUISmfi8eCVHWM0E9yxDaw='];
            var expected = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                            "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                            'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.decryptDataMessage(atob(tests[i]), key, iv);
                assert.strictEqual(result, expected[i]);
            }
        });

        it('data messages with exponential padding', function() {
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['6XKTgeuvwFtdRmFP7IaF4rSVaXJMqW8OETTe9B9AZwY=',
                         'M5HrNJxP+snqy6OuVNQvYAe6SSvZaAF0Kef3eysHGU4=',
                         'tMj2YWriiLT1pzthGVly/oBScpN7XraZ2byXvJTfA98=',
                         'QyfKqgn9g0A6LZDpjLTupLwnw0UYldJyHx2uOOMhNVI=',
                         'VtT8MtqFepiSohOU2RiikNw75ts+DzWmzM5n9NOwPRrlFQ1xxTCP5eVzFNt+ZBCpmYJojdVrVsIM714z8QsI5g==',
                         'NrTBK7A3vRIpKuN9SMw8uMPFUXuznTB+/nSx4MFJ2do=',
                         'vXWdTN0pKmL9W7TRZN4nfcZkoAAlGcuRJpdupKe34wk=',
                         'gsou4Ncoykbkg4NHm19CMUNzO0YA/BEwAzNqdCJxkbc='];
            var expected = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                            "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                            'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.decryptDataMessage(atob(tests[i]), key, iv);
                assert.strictEqual(result, expected[i]);
            }
        });
    });

    describe("encryptDataMessage()/decryptDataMessage()", function() {
        it('several round trips', function() {
            for (var i = 0; i < 5; i++) {
                var key = jodid25519.utils.bytes2string(utils._newKey08(128));
                var messageLength = Math.floor(256 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var encryptResult = ns.encryptDataMessage(message, key);
                var cipher = encryptResult.data;
                var iv = encryptResult.iv;
                var clear = ns.decryptDataMessage(cipher, key, iv);
                assert.strictEqual(message, clear);
            }
        });
    });

    describe("signDataMessage()", function() {
        it('null equivalents', function() {
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.signDataMessage(tests[i],
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY), null);
            }
        });

        it('data messages', function() {
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS'];
            var expected = ['5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==',
                            'drcfMQxOrWHPERrOaIyo4H1H2laq09YRgyC669W2upOuCWbARC6xMpaGaQWFRkp4WAV8Jc0qMnmNNF8hyPaIDQ==',
                            '5F4lOmulZwLZ5uRje/RtkyD1wz1U8mVPdv15Ix2BIFb9UM14zA0H8hBk/xZOo2rkaKMM+tCUGrnlq6u4LqGUBg==',
                            'pTojkkKs54p8T7yKcHKmBs3rso5ZkA9LBgcrlh+j3qViEzHrsrLaigq7ANb6JfMoXK6jSIKl5RwHtYb7+DGdDg==',
                            'k6sBjSrQTioI9UVJNusYDqC/Hrn/3/FZTTH5upe2FVavgYngFg+s/xr3SzJIXk5QW6A+pzQxBIvz3zo83h3fBA==',
                            'Uy2YERg9X05Ynpt6B6Wg8jAJuBQZr6BXbeHAkkcQbirODJgpWZlTSuKm2T2EnO7RtACQwChEEXb6DfaEFff+AA=='];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.signDataMessage(tests[i], _td.ED25519_PRIV_KEY,  _td.ED25519_PUB_KEY);
                assert.strictEqual(btoa(result), expected[i], 'case ' + (i + 1));
            }
        });
    });

    describe("verifyDataMessage()", function() {
        it('verifies', function() {
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS']; // <-- this should verify!!!
            var signatures = ['5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==',
                              'drcfMQxOrWHPERrOaIyo4H1H2laq09YRgyC669W2upOuCWbARC6xMpaGaQWFRkp4WAV8Jc0qMnmNNF8hyPaIDQ==',
                              '5F4lOmulZwLZ5uRje/RtkyD1wz1U8mVPdv15Ix2BIFb9UM14zA0H8hBk/xZOo2rkaKMM+tCUGrnlq6u4LqGUBg==',
                              'pTojkkKs54p8T7yKcHKmBs3rso5ZkA9LBgcrlh+j3qViEzHrsrLaigq7ANb6JfMoXK6jSIKl5RwHtYb7+DGdDg==',
                              'k6sBjSrQTioI9UVJNusYDqC/Hrn/3/FZTTH5upe2FVavgYngFg+s/xr3SzJIXk5QW6A+pzQxBIvz3zo83h3fBA==',
                              'Uy2YERg9X05Ynpt6B6Wg8jAJuBQZr6BXbeHAkkcQbirODJgpWZlTSuKm2T2EnO7RtACQwChEEXb6DfaEFff+AA=='];
            for (var i = 0; i < tests.length; i++) {
                assert.ok(ns.verifyDataMessage(tests[i], atob(signatures[i]), _td.ED25519_PUB_KEY),
                          'case ' + (i + 1));
            }
        });

        it('failes verification', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS', ''];
            var signatures = ['5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==',
                              'drcfMQxOrWHPERrOaIyo4H1H2laq09YRgyC669W2upOuCWbARC6xMpaGaQWFRkp4WAV8Jc0qMnmNNF8hyPaIDQ==',
                              '5F4lOmulZwLZ5uRje/RtkyD1wz1U8mVPdv15Ix2BIFb9UM14zA0H8hBk/xZOo2rkaKMM+tCUGrnlq6u4LqGUBg==',
                              'pTojkkKs54p8T7yKcHKmBs3rso5ZkA9LBgcrlh+j3qViEzHrsrLaigq7ANb6JfMoXK6jSIKl5RwHtYb7+DGdDg==',
                              'k6sBjSrQTioI9UVJNusYDqC/Hrn/3/FZTTH5upe2FVavgYngFg+s/xr3SzJIXk5QW6A+pzQxBIvz3zo83h3fBA==',
                              'Uy2YERg9X05Ynpt6B6Wg8jAJuBQZr6BXbeHAkkcQbirODJgpWZlTSuKm2T2EnO7RtACQwChEEXb6DfaEFff+AA=='];
            for (var i = 0; i < tests.length; i++) {
                assert.notOk(ns.verifyDataMessage(tests[i],
                                                  atob(signatures[i]),
                                                  _td.ED25519_PUB_KEY));
            }
        });
    });

    describe("signDataMessage()/verifyDataMessage()", function() {
        it('several round trips', function() {
            for (var i = 0; i < 5; i++) {
                var privKey = jodid25519.utils.bytes2string(utils._newKey08(512));
                var pubKey = jodid25519.eddsa.publicKey(privKey);
                var messageLength = Math.floor(1024 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var signature = ns.signDataMessage(message, privKey, pubKey);
                assert.ok(ns.verifyDataMessage(message, signature, pubKey),
                          'iteration ' + (i + 1));
            }
        });
    });

    describe("getQueryMessage()", function() {
        it('simple invocations', function() {
            var tests = ['',
                         'foo'];
            var expected = ['?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?',
                            '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?foo'];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.getQueryMessage(tests[i]), expected[i]);
            }
        });
    });

    describe("getErrorMessage()", function() {
        it('simple invocations', function() {
            var tests = ['',
                         'Problem retrieving public key for: PointyHairedBoss'];
            var expected = ['?mpENC Error:.',
                            '?mpENC Error:Problem retrieving public key for: PointyHairedBoss.'];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.getErrorMessage(tests[i]), expected[i]);
            }
        });
    });
});
