/**
 * @fileOverview
 * Test of the `mpenc/codec` module.
 */

/*
 * Created: 19 Mar 2014-2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/codec",
    "mpenc/version",
    "mpenc/helper/utils",
    "jodid25519",
    "asmcrypto",
    "megalogger",
    "chai",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, version, utils, jodid25519, asmCrypto, MegaLogger,
            chai, sinon_sandbox, sinon_assert) {
    "use strict";

    var assert = chai.assert;

    // set test data
    _td.DATA_MESSAGE_CONTENT.protocol = version.PROTOCOL_VERSION;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        sandbox.stub(MegaLogger._logRegistry.codec, '_log');
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
                             [1, '\u0001'],
                             [14, 0]];
                var expected = ['\u0000\u0000\u0000\u0005hello',
                                "\u0000\u002a\u0000\u000cDon't panic!",
                                'Sl\u0000\u0020' + _td.SESSION_ID,
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u0001\u0000\u0001\u0001',
                                '\u0000\u000e\u0000\u0001\u0030'];
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
                             '\u0000\u000e\u0000\u0001\u0030',
                             '\u0000\u0000\u0000\u0005hello\u0000\u0000\u0000\u0005world'];
                var expected = [[0, 'hello', ''],
                                [42, "Don't panic!", ''],
                                [21356, _td.SESSION_ID, ''],
                                [14, '', '***'],
                                [14, '0', ''],
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

        describe("getMessageType()", function() {
            it('empty content', function() {
                var tests = [null, undefined, ''];
                for (var i = 0; i < tests.length; i++) {
                    assert.notOk(ns.getMessageType(tests[i]));
                }
            });

            it('greet message', function() {
                assert.strictEqual(ns.getMessageType(_td.DOWNFLOW_MESSAGE_STRING),
                                   ns.MESSAGE_TYPE.QUIT_DOWN);
            });

            it('data message', function() {
                assert.ok(ns.getMessageType(_td.DATA_MESSAGE_STRING),
                          ns.MESSAGE_TYPE.PARTICIPANT_DATA);
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
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result, 60);
            });

            it('upflow message binary', function() {
                var result = ns.encodeMessageContent(_td.UPFLOW_MESSAGE_CONTENT,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result, _td.UPFLOW_MESSAGE_STRING);
            });

            it('downflow message for quit', function() {
                sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
                var result = ns.encodeMessageContent(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.lengthOf(result, 24);
            });

            it('downflow message for quit binary', function() {
                var result = ns.encodeMessageContent(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY);
                assert.strictEqual(result, _td.DOWNFLOW_MESSAGE_STRING);
            });

            it('data message', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                var result = ns.encodeMessageContent('foo',
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker);
                // 4 TLVs with 109 bytes:
                // signature (4 + 64), protocol v (4 + 1), msg. type (4 + 2),
                // sid/key hint (4 + 1), IV (4 + 12), encr. message (4 + 6)
                // (incl. length and extra NULL)
                assert.lengthOf(result, 110);
            });

            it('data message with second group key', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID, 'foo'],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY, 'foo']
                };
                sessionTracker.sessions['foo'] = {};
                var result = ns.encodeMessageContent('foo',
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker);
                // 4 TLVs with 109 bytes:
                // signature (4 + 64), protocol v (4 + 1), msg. type (4 + 2),
                // sid/key hint (4 + 1), IV (4 + 12), encr. message (4 + 6)
                // (incl. length and extra NULL)
                assert.lengthOf(result, 110);
            });

            it('data message with exponential padding', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                var result = ns.encodeMessageContent('foo',
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker, 32);
                // 4 TLVs with 136 bytes:
                // signature (4 + 64), protocol v (4 + 1), msg. type (4 + 2),
                // sid/key hint (4 + 1), IV (4 + 12), encr. message (4 + 32)
                assert.lengthOf(result, 136);
            });
        });

        describe("decodeMessageContent()", function() {
            it('upflow message', function() {
                var result = ns.decodeMessageContent(_td.UPFLOW_MESSAGE_STRING,
                                                     _td.ED25519_PUB_KEY, {});
                assert.strictEqual(result.source, _td.UPFLOW_MESSAGE_CONTENT.source);
                assert.strictEqual(result.dest, _td.UPFLOW_MESSAGE_CONTENT.dest);
                assert.strictEqual(result.messageType, _td.UPFLOW_MESSAGE_CONTENT.messageType);
                assert.deepEqual(result.members, _td.UPFLOW_MESSAGE_CONTENT.members);
                assert.deepEqual(result.intKeys, _td.UPFLOW_MESSAGE_CONTENT.intKeys);
                assert.deepEqual(result.nonces, _td.UPFLOW_MESSAGE_CONTENT.nonces);
                assert.deepEqual(result.pubKeys, _td.UPFLOW_MESSAGE_CONTENT.pubKeys);
                assert.strictEqual(result.sessionSignature, _td.UPFLOW_MESSAGE_CONTENT.sessionSignature);
            });

            it('upflow message, debug on', function() {
                ns.decodeMessageContent(_td.UPFLOW_MESSAGE_STRING,
                                        _td.ED25519_PUB_KEY, {});
                var log = MegaLogger._logRegistry.codec._log.getCall(0).args;
                assert.deepEqual(log, [0, ['mpENC decoded message debug: ',
                                           ['messageSignature: scAkAakFr5dC1DF4Ig+MJIyDbSszesDeG1xIjtXXmLdTnjmAxTjUdljZifIEkElVvJ8JqfjaxbUTrdo2m1MABA==',
                                            'protocol: 1',
                                            'messageType: 0x9c (INIT_INITIATOR_UP)',
                                            'from: 1', 'to: 2',
                                            'member: 1', 'member: 2', 'member: 3', 'member: 4', 'member: 5', 'member: 6',
                                            'intKey: ', 'intKey: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                            'nonce: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                            'pubKey: 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=']]]);
            });

            it('downflow message for quit', function() {
                var result = ns.decodeMessageContent(_td.DOWNFLOW_MESSAGE_STRING,
                                                     _td.ED25519_PUB_KEY, {});
                assert.strictEqual(result.source, _td.DOWNFLOW_MESSAGE_CONTENT.source);
                assert.strictEqual(result.dest, _td.DOWNFLOW_MESSAGE_CONTENT.dest);
                assert.strictEqual(result.messageType, _td.DOWNFLOW_MESSAGE_CONTENT.messageType);
                assert.strictEqual(result.signingKey, _td.DOWNFLOW_MESSAGE_CONTENT.signingKey);
            });

            it('wrong protocol version', function() {
                var message = _td.UPFLOW_MESSAGE_STRING.substring(68, 72)
                            + String.fromCharCode(77)
                            + _td.UPFLOW_MESSAGE_STRING.substring(73);
                assert.throws(function() { ns.decodeMessageContent(message, _td.ED25519_PUB_KEY, {}); },
                              'Received wrong protocol version: 77');
            });

            it('data message', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                var result = ns.decodeMessageContent(_td.DATA_MESSAGE_STRING,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker);
                assert.lengthOf(result.signature, 64);
                assert.strictEqual(result.signatureOk, _td.DATA_MESSAGE_CONTENT.signatureOk);
                assert.strictEqual(result.protocol, _td.DATA_MESSAGE_CONTENT.protocol);
                assert.lengthOf(result.iv, 12);
                assert.strictEqual(result.data, _td.DATA_MESSAGE_CONTENT.data);
            });

            it('data message with second group key', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY, 'foo']
                };
                var result = ns.decodeMessageContent(_td.DATA_MESSAGE_STRING2,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker);
                assert.lengthOf(result.signature, 64);
                assert.strictEqual(result.signatureOk, _td.DATA_MESSAGE_CONTENT.signatureOk);
                assert.strictEqual(result.protocol, _td.DATA_MESSAGE_CONTENT.protocol);
                assert.lengthOf(result.iv, 12);
                assert.strictEqual(result.data, _td.DATA_MESSAGE_CONTENT.data);
            });

            it('data message, debug on', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                ns.decodeMessageContent(_td.DATA_MESSAGE_STRING,
                                        _td.ED25519_PUB_KEY, sessionTracker);

                var log = MegaLogger._logRegistry.codec._log.getCall(0).args;
                assert.deepEqual(log, [0, ['mpENC decoded message debug: ',
                                           ['messageSignature: K6P9bTi9HOL1qvafIOexS0eaIS1yfNgk5EDGU5Me2a9xiJEq5Be7r7WSTHXq+jJEDADmGR1hFVn90tvQYQm9Cg==',
                                            'protocol: 1',
                                            'messageType: 0x0 (PARTICIPANT_DATA)',
                                            'sidkeyHint: 0x1e',
                                            'messageIV: rTSUkx7AnujlVtHT',
                                            'rawDataMessage: 21YjH0WU',
                                            'decryptDataMessage: foo']]]);
            });

            it('data message with exponential padding', function() {
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                var result = ns.decodeMessageContent(_td.DATA_MESSAGE_STRING32,
                                                     _td.ED25519_PUB_KEY,
                                                     sessionTracker);
                assert.lengthOf(result.signature, 64);
                assert.strictEqual(result.signatureOk, _td.DATA_MESSAGE_CONTENT.signatureOk);
                assert.strictEqual(result.protocol, _td.DATA_MESSAGE_CONTENT.protocol);
                assert.lengthOf(result.iv, 12);
                assert.strictEqual(result.data, _td.DATA_MESSAGE_CONTENT.data);
            });

            it('data message, invalid signature', function() {
                // Change a single byte.
                var message = _td.DATA_MESSAGE_STRING.substring(0, 10)
                            + String.fromCharCode(77)
                            + _td.DATA_MESSAGE_STRING.substring(11);
                var sessionTracker = { sessionIDs: [_td.SESSION_ID],
                                       sessions: {} };
                sessionTracker.sessions[_td.SESSION_ID] = {
                    sid: _td.SESSION_ID,
                    members: ['Moe', 'Larry', 'Curly'],
                    groupKeys: [_td.GROUP_KEY]
                };
                assert.throws(function() { ns.decodeMessageContent(message,
                                                                   _td.ED25519_PUB_KEY,
                                                                   sessionTracker); },
                              'Signature of message does not verify');
            });
        });

        describe("inspectMessageContent()", function() {
            it('upflow message', function() {
                var result = ns.inspectMessageContent(_td.UPFLOW_MESSAGE_STRING);
                assert.strictEqual(result.protocolVersion, 1);
                assert.strictEqual(result.messageType, 0x9c);
                assert.strictEqual(result.messageTypeString, 'INIT_INITIATOR_UP');
                assert.strictEqual(result.from, '1');
                assert.strictEqual(result.to, '2');
                assert.strictEqual(result.origin, 'initiator');
                assert.strictEqual(result.operation, 'START');
                assert.strictEqual(result.agreement, 'initial, GKE, SKE');
                assert.strictEqual(result.flow, 'up');
                assert.strictEqual(result.recover, false);
                assert.deepEqual(result.members, ['1', '2', '3', '4', '5', '6']);
                assert.strictEqual(result.numNonces, 1);
                assert.strictEqual(result.numIntKeys, 2);
                assert.strictEqual(result.numPubKeys, 1);
            });

            it('downflow message for quit', function() {
                var result = ns.inspectMessageContent(_td.DOWNFLOW_MESSAGE_STRING);
                assert.strictEqual(result.protocolVersion, 1);
                assert.strictEqual(result.messageType, 0xd3);
                assert.strictEqual(result.messageTypeString, 'QUIT_DOWN');
                assert.strictEqual(result.from, '1');
                assert.strictEqual(result.to, '');
                assert.strictEqual(result.origin, '???');
                assert.strictEqual(result.operation, 'QUIT');
                assert.strictEqual(result.agreement, 'auxiliary');
                assert.strictEqual(result.flow, 'down');
                assert.strictEqual(result.recover, false);
                assert.deepEqual(result.members, []);
                assert.strictEqual(result.numNonces, 0);
                assert.strictEqual(result.numIntKeys, 0);
                assert.strictEqual(result.numPubKeys, 0);
            });
        });
    });

    describe("encodeMessage()", function() {
        it('upflow message', function() {
            sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeMessage(_td.UPFLOW_MESSAGE_CONTENT, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY, {});
            assert.strictEqual(result, '?mpENC:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.');
        });

        it('upflow message binary', function() {
            var result = ns.encodeMessage(_td.UPFLOW_MESSAGE_CONTENT, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY, {});
            assert.strictEqual(result, _td.UPFLOW_MESSAGE_PAYLOAD);
        });

        it('downflow message on quit', function() {
            var message = _td.DOWNFLOW_MESSAGE_CONTENT;
            sandbox.stub(ns, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeMessage(message, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY, {});
            assert.strictEqual(result, '?mpENC:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.');
        });

        it('downflow message on quit binary', function() {
            var result = ns.encodeMessage(_td.DOWNFLOW_MESSAGE_CONTENT,
                                          _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, {});
            assert.strictEqual(result, _td.DOWNFLOW_MESSAGE_PAYLOAD);
        });

        it('null message', function() {
            assert.strictEqual(ns.encodeMessage(null,
                                                _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, {}),
                               null);
            assert.strictEqual(ns.encodeMessage(undefined,
                                                _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, {}),
                               null);
        });

        it('data message', function() {
            var message = 'wha tekau ma rua';
            sandbox.stub(ns, 'encodeMessageContent').returns('42');
            var result = ns.encodeMessage(message, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY, {});
            sinon_assert.calledOnce(ns.encodeMessageContent);
            assert.deepEqual(ns.encodeMessageContent.getCall(0).args,
                               [message, _td.ED25519_PRIV_KEY,
                                _td.ED25519_PUB_KEY, {}, 0]);
            assert.strictEqual(result, '?mpENC:NDI=.');
        });

        it('data message with exponential padding', function() {
            var message = 'wha tekau ma rua';
            sandbox.stub(ns, 'encodeMessageContent').returns('42');
            var result = ns.encodeMessage(message, _td.ED25519_PRIV_KEY,
                                          _td.ED25519_PUB_KEY, {}, 32);
            sinon_assert.calledOnce(ns.encodeMessageContent);
            assert.deepEqual(ns.encodeMessageContent.getCall(0).args,
                             [message, _td.ED25519_PRIV_KEY,
                              _td.ED25519_PUB_KEY, {}, 32]);
            assert.strictEqual(result, '?mpENC:NDI=.');
        });
    });

    describe("encodeErrorMessage()", function() {
        it('with signature', function() {
            var from = 'a.dumbledore@hogwarts.ac.uk/android123';
            var severity = 'TERMINAL';
            var message = 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
            sandbox.stub(ns, 'signDataMessage').returns('\u0000\u0000\u0000');
            var result = ns.encodeErrorMessage(from, severity, message, _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY);
            sinon_assert.calledOnce(ns.signDataMessage);
            assert.strictEqual(result, '?mpENC Error:AAAA:from "a.dumbledore@hogwarts.ac.uk/android123"'
                               + ':TERMINAL:Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.');
        });

        it('without signature', function() {
            var from = 'a.dumbledore@hogwarts.ac.uk/android123';
            var severity = 'TERMINAL';
            var message = 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
            sandbox.stub(ns, 'signDataMessage').returns('\u0000\u0000\u0000');
            var result = ns.encodeErrorMessage(from, severity, message);
            assert.strictEqual(ns.signDataMessage.callCount, 0);
            assert.strictEqual(result, '?mpENC Error::from "a.dumbledore@hogwarts.ac.uk/android123"'
                               + ':TERMINAL:Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.');
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
            var iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
            var expected = ['6H3l',
                            '6H/R1sI=',
                            '6HGhi6z7+lgyR6wtKsss',
                            '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2LrZ',
                            '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJBw=',
                            '6HexIFGySvliTa0hSQ==',
                            '6G2tJ2ay/R0uBuRkDphJAkEVGQ==',
                            '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0Rw=='];
            sandbox.stub(utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.encryptDataMessage(tests[i], key);
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
                var result = ns.encryptDataMessage(tests[i], key, paddingSize);
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
            var expected = ['6H3l',
                            '6H/R1sI=',
                            '6HGhi6z7+lgyR6wtKsss',
                            '6GWjiLu14B9idbIlLoJJAlAQOcEsFclM2LrZ',
                            '6E+1jOWy6RQ3T+IpLoZbUUoYf+RjOM5QyKSxWMFkYKMNjjLyqULHdMCG5LjVKyDeGIOAJBw=',
                            '6HexIFGySvliTa0hSQ==',
                            '6G2tJ2ay/R0uBuRkDphJAkEVGQ==',
                            '6GE1RRJnXsiTphPGmVL8x/TJyAyS+Wu8bXgIrDC0Rw=='];
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
            var iv = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b'));
            var key = jodid25519.utils.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.decryptDataMessage(tests[i], key, iv), null);
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
                var result = ns.decryptDataMessage(atob(tests[i]), key, iv);
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

    describe("_messageTypeFromNumber() and _messageTypeToNumber()", function() {
        var messageTypes = {// Data message.
                            '\u0000\u0000': 0x000, // PARTICIPANT_DATA
                            // Initial start sequence.
                            '\u0000\u009c': 0x09c, // INIT_INITIATOR_UP
                            '\u0000\u001c': 0x01c, // INIT_PARTICIPANT_UP
                            '\u0000\u001e': 0x01e, // INIT_PARTICIPANT_DOWN
                            '\u0000\u001a': 0x01a, // INIT_PARTICIPANT_CONFIRM_DOWN
                            '\u0001\u009c': 0x19c, // RECOVER_INIT_INITIATOR_UP
                            '\u0001\u001c': 0x11c, // RECOVER_INIT_PARTICIPANT_UP
                            '\u0001\u001e': 0x11e, // RECOVER_INIT_PARTICIPANT_DOWN
                            '\u0001\u001a': 0x11a, // RECOVER_INIT_PARTICIPANT_CONFIRM_DOWN:
                            // Join sequence.
                            '\u0000\u00ad': 0x0ad, // JOIN_AUX_INITIATOR_UP
                            '\u0000\u002d': 0x02d, // JOIN_AUX_PARTICIPANT_UP
                            '\u0000\u002f': 0x02f, // JOIN_AUX_PARTICIPANT_DOWN
                            '\u0000\u002b': 0x02b, // JOIN_AUX_PARTICIPANT_CONFIRM_DOWN
                            // Exclude sequence.
                            '\u0000\u00bf': 0x0bf, // EXCLUDE_AUX_INITIATOR_DOWN
                            '\u0000\u003b': 0x03b, // EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN
                            '\u0001\u00bf': 0x1bf, // RECOVER_EXCLUDE_AUX_INITIATOR_DOWN
                            '\u0001\u003b': 0x13b, // RECOVER_EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN
                            // Refresh sequence.
                            '\u0000\u00c7': 0x0c7, // REFRESH_AUX_INITIATOR_DOWN
                            '\u0000\u0047': 0x047, // REFRESH_AUX_PARTICIPANT_DOWN
                            '\u0001\u00c7': 0x1c7, // RECOVER_REFRESH_AUX_INITIATOR_DOWN
                            '\u0001\u0047': 0x147, // RECOVER_REFRESH_AUX_PARTICIPANT_DOWN:
                            // Quit indication.
                            '\u0000\u00d3': 0x0d3  // QUIT_DOWN
        };
        var messageTypeNumbers = {};
        for (var msgType in messageTypes) {
            messageTypeNumbers[messageTypes[msgType]] = msgType;
        }

        it('_messageTypeFromNumber()', function() {
            for (var number in messageTypeNumbers) {
                assert.strictEqual(ns._messageTypeFromNumber(number),
                                   messageTypeNumbers[number]);
            }
        });

        it('_messageTypeToNumber()', function() {
            for (var type in messageTypes) {
                assert.strictEqual(ns._messageTypeToNumber(type),
                                   messageTypes[type]);
            }
        });

        it('round trip', function() {
            for (var type in messageTypes) {
                var number = ns._messageTypeToNumber(type);
                assert.strictEqual(ns._messageTypeFromNumber(number), type);
            }
        });
    });

    describe("ProtocolMessage class", function() {
        describe("_readBit()", function() {
            it('downflow on INIT_PARTICIPANT_UP', function() {
                var message = new ns.ProtocolMessage();
                message.messageType = '\u0000\u001c', // INIT_PARTICIPANT_UP
                assert.strictEqual(message._readBit(ns._DOWN_BIT), false);
            });

            it('downflow on QUIT_DOWN', function() {
                var message = new ns.ProtocolMessage();
                message.messageType = '\u0000\u00d3'; // QUIT_DOWN
                assert.strictEqual(message._readBit(ns._DOWN_BIT), true);
            });
        });

        describe("_setBit()", function() {
            it('on valid transitions', function() {
                var message = new ns.ProtocolMessage();
                var tests = [[ns.MESSAGE_TYPE.INIT_PARTICIPANT_UP, ns._DOWN_BIT, true],
                             [ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN, ns._DOWN_BIT, true],
                             [ns.MESSAGE_TYPE.INIT_INITIATOR_UP, ns._INIT_BIT, false],
                             [ns.MESSAGE_TYPE.INIT_PARTICIPANT_UP, ns._INIT_BIT, false]];
                var expected = [ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN,
                                ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN,
                                ns.MESSAGE_TYPE.INIT_PARTICIPANT_UP,
                                ns.MESSAGE_TYPE.INIT_PARTICIPANT_UP];
                for (var i in tests) {
                    message.messageType = tests[i][0];
                    var bit = tests[i][1];
                    var targetValue = tests[i][2];
                    message._setBit(bit, targetValue);
                    assert.strictEqual(message.messageType, expected[i]);
                }
            });

            it('on invalid transitions', function() {
                var message = new ns.ProtocolMessage();
                var tests = [[ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN, ns._DOWN_INIT, true],
                             [ns.MESSAGE_TYPE.INIT_PARTICIPANT_CONFIRM_DOWN, ns._DOWN_BIT, false]];
                for (var i in tests) {
                    message.messageType = tests[i][0];
                    var bit = tests[i][1];
                    var targetValue = tests[i][2];
                    assert.throws(function() { message._setBit(bit, targetValue); },
                                  'Illegal message type!');
                }
            });

            it('on silenced invalid transitions', function() {
                var message = new ns.ProtocolMessage();
                var tests = [[ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN, ns._DOWN_INIT, true],
                             [ns.MESSAGE_TYPE.INIT_PARTICIPANT_CONFIRM_DOWN, ns._DOWN_BIT, false]];
                for (var i in tests) {
                    message.messageType = tests[i][0];
                    var bit = tests[i][1];
                    var targetValue = tests[i][2];
                    message._setBit(bit, targetValue, true);
                    assert.match(MegaLogger._logRegistry.codec._log.getCall(i).args[1],
                                 /^Arrived at an illegal message type, but was told to ignore it:/);
                    assert.notStrictEqual(message.messageType, tests[i][0]);
                }
            });
        });

        describe("#clearGKA(), isGKA()", function() {
            it('on valid transitions', function() {
                var message = new ns.ProtocolMessage();
                var tests = [ns.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN,
                             ns.MESSAGE_TYPE.INIT_PARTICIPANT_CONFIRM_DOWN];
                for (var i in tests) {
                    message.messageType = tests[i];
                    message.clearGKA();
                    assert.strictEqual(message.isGKA(), false);
                }
            });
        });
    });
});
