/**
 * @fileOverview
 * Test of the `mpenc/codec` module.
 */

/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2016 by Mega Limited, Auckland, New Zealand
 *     https://mega.nz/
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
    "mpenc/codec",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "asmcrypto",
    "megalogger",
    "chai",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, codec, struct, utils, asmCrypto, MegaLogger,
            chai, sinon_sandbox) {
    "use strict";

    var assert = chai.assert;
    var ImmutableSet = struct.ImmutableSet;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    function _dummyMessageSecurity(paddingSize) {
        return new ns.MessageSecurity({
            id: 'Moe',
            sessionId: _td.SESSION_ID,
            members : ['Moe', 'Larry', 'Curly'],
            groupKey : _td.GROUP_KEY,
            ephemeralPrivKey : _td.ED25519_PRIV_KEY,
            ephemeralPubKey : _td.ED25519_PUB_KEY,
            pubKeyMap : { 'Moe': _td.ED25519_PUB_KEY },
        }, paddingSize);
    }

    var defaultReaders = new ImmutableSet(['Larry', 'Curly']);

    describe("DefaultMessageCodec", function() {
        var codec = ns.DefaultMessageCodec;
        var assertEncodeDecode = function(body) {
            assert.deepEqual(body, codec.decode(codec.encode(body)));
        };

        it("encode-decode", function() {
            assertEncodeDecode(new ns.Payload("hello"));
            assertEncodeDecode(new ns.ExplicitAck(true));
            assertEncodeDecode(new ns.ExplicitAck(false));
            assertEncodeDecode(new ns.Consistency(true));
            assertEncodeDecode(new ns.Consistency(false));
        });

        it("encode fail", function() {
            assert.throws(codec.encode.bind(null, null));
            assert.throws(codec.encode.bind(null, undefined));
            assert.throws(codec.encode.bind(null, new ns.Message("", [], "", [], new ns.Payload("x"))));
            assert.throws(codec.encode.bind(null, {}));
            assert.throws(codec.encode.bind(null, []));
        });

        it("decode fail", function() {
            assert.throws(codec.decode.bind(null, null));
            assert.throws(codec.decode.bind(null, ""));
            assert.throws(codec.decode.bind(null, '[]'));
            assert.throws(codec.decode.bind(null, '\x00{}'));
            assert.throws(codec.decode.bind(null, '\xff[""]'));
            // specific values
            assert.throws(codec.decode.bind(null, '\x00[]'));
            assert.throws(codec.decode.bind(null, '\x00[123]'));
            assert.throws(codec.decode.bind(null, '\x00[false]'));
            assert.throws(codec.decode.bind(null, '\x01[]'));
            assert.throws(codec.decode.bind(null, '\x01[123]'));
            assert.throws(codec.decode.bind(null, '\x01["x"]'));
            assert.throws(codec.decode.bind(null, '\x03[]'));
            assert.throws(codec.decode.bind(null, '\x03[123]'));
            assert.throws(codec.decode.bind(null, '\x03["x"]'));
        });

    });


    describe("MessageSecurity.authEncrypt()", function() {
        it('data message', function() {
            var result = _dummyMessageSecurity().authEncrypt(null, {
                author: 'Moe',
                parents: null,
                readers: defaultReaders,
                body: "foo"
            });
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 1), IV (4 + 12), encr. message (4 + (4 + 5))
            assert.lengthOf(codec.decodeWirePacket(result.pubtxt).content, 112);
        });

        it('data message with exponential padding', function() {
            var result = _dummyMessageSecurity(32).authEncrypt(null, {
                author: 'Moe',
                parents: null,
                readers: defaultReaders,
                body: "foo"
            });
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 1), IV (4 + 12), encr. message (4 + 32)
            assert.lengthOf(codec.decodeWirePacket(result.pubtxt).content, 135);
        });

        it('data message with parents', function() {
            var result = _dummyMessageSecurity().authEncrypt(null, {
                author: 'Moe',
                parents: new ImmutableSet(["abcd", "1234"]),
                readers: defaultReaders,
                body: "foo"
            });
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 1), IV (4 + 12), encr. message (4 + (4 + 5 + parents (4 + 4) * 2))
            assert.lengthOf(codec.decodeWirePacket(result.pubtxt).content, 128);
        });

        it('data message with parents and padding', function() {
            var result = _dummyMessageSecurity(32).authEncrypt(null, {
                author: 'Moe',
                parents: new ImmutableSet(["abcd", "1234"]),
                readers: defaultReaders,
                body: "foo"
            });
            // sid/key hint (4 + 1), signature (4 + 64), protocol v (4 + 1),
            // msg. type (4 + 1), IV (4 + 12), encr. message (4 + 32)
            assert.lengthOf(codec.decodeWirePacket(result.pubtxt).content, 135);
        });
    });

    describe("MessageSecurity.decrypt()", function() {
        it('data message', function() {
            var result = _dummyMessageSecurity().decryptVerify(null, codec.encodeWirePacket(_td.DATA_MESSAGE_STRING), 'Moe');

            assert.strictEqual(result.message.author, 'Moe');
            assert.strictEqual(result.message.body, _td.DATA_MESSAGE_CONTENT.data);
        });

        it('data message with exponential padding', function() {
            var result = _dummyMessageSecurity().decryptVerify(null, codec.encodeWirePacket(_td.DATA_MESSAGE_STRING32), 'Moe');

            assert.strictEqual(result.message.author, 'Moe');
            assert.strictEqual(result.message.body, _td.DATA_MESSAGE_CONTENT.data);
        });
    });

    describe("encrypt-decrypt with arbitrary unicode text", function() {
        var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                     "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                     'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];

        it('data messages', function() {
            this.timeout(this.timeout() * 5);
            for (var i = 0; i < tests.length; i++) {
                var mSecurity = _dummyMessageSecurity();
                var encrypted = mSecurity.authEncrypt(null, {
                    author: "Moe",
                    parents: null,
                    readers: defaultReaders,
                    body: tests[i],
                }).pubtxt;
                var result = mSecurity.decryptVerify(null, encrypted, 'Moe');
                assert.strictEqual(result.message.author, 'Moe');
                assert.strictEqual(result.message.body, tests[i]);
            }
        });

        it('data messages with exponential padding', function() {
            this.timeout(this.timeout() * 5);
            for (var i = 0; i < tests.length; i++) {
                var mSecurity = _dummyMessageSecurity(32);
                var encrypted = mSecurity.authEncrypt(null, {
                    author: "Moe",
                    parents: null,
                    readers: defaultReaders,
                    body: tests[i],
                }).pubtxt;
                var result = mSecurity.decryptVerify(null, encrypted, 'Moe');
                assert.strictEqual(result.message.author, 'Moe');
                assert.strictEqual(result.message.body, tests[i]);
                var tlv = codec.decodeWirePacket(encrypted).content;
                assert(tlv.length === 135 || tlv.length === 135 + 32);
            }
        });
    });

    describe("_encryptRaw()/_decryptRaw()", function() {
        it('several round trips', function() {
            for (var i = 0; i < 5; i++) {
                var key = utils.randomString(16);
                var messageLength = Math.floor(256 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var encryptResult = ns._encryptRaw(message, key);
                var cipher = encryptResult.data;
                var iv = encryptResult.iv;
                var clear = ns._decryptRaw(cipher, key, iv);
                assert.strictEqual(message, clear);
            }
        });
    });

});
