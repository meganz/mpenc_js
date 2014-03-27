/**
 * @fileOverview
 * Test of the `mpenc.greet.ske` module (Signature Key Exchange).
 */

define([
    "mpenc/greet/ske",
    "mpenc/util/utils",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
], function(ns, utils, chai, sinon_assert, sinon_sandbox, sinon_spy) {
    "use strict";

    /*
     * Created: 5 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

    var assert = chai.assert;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("module level", function() {
        describe('_binstring2mpi()', function() {
            it('convert message to MPI representation', function() {
                var messages = ['foo', 'The answer is 42!'];
                var expected = [[6713199],
                                [3420705, 33986354, 58156402, 33953511, 5531749]];
                for (var i = 0; i < messages.length; i++) {
                    var result = ns._binstring2mpi(messages[i]);
                    assert.deepEqual(result, expected[i]);
                }
            });
        });

        describe('_mpi2binstring()', function() {
            it('convert message from MPI representation', function() {
                var messages = [[6713199],
                                [3420705, 33986354, 58156402, 33953511, 5531749]];
                var expected = ['foo', 'The answer is 42!'];
                for (var i = 0; i < messages.length; i++) {
                    var result = ns._mpi2binstring(messages[i]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });

        describe('_pkcs1v15_encode()', function() {
            it('convert message to PKCS#1 v1.5 encoding', function() {
                var messages = ['foo', 'Klaatu barada nikto.', _td.SESSION_ID];
                for (var i = 0; i < messages.length; i++) {
                    var result = ns._pkcs1v15_encode(messages[i], 256);
                    assert.lengthOf(result, 256);
                }
            });

            it('encoding fail on too big message', function() {
                var message = ns._mpi2binstring(_td.RSA_PUB_KEY[0]);
                assert.throws(function() { ns._pkcs1v15_encode(message, 256); },
                              'message too long for encoding scheme');
            });
        });

        describe('_pkcs1v15_decode()', function() {
            it('decoding fail on too small message', function() {
                assert.throws(function() { ns._pkcs1v15_decode('foo'); },
                              'message decoding error');
            });
        });

        describe('_pkcs1v15_encode()/_pkcs1v15_decode()', function() {
            it('roundtrip convert message with PKCS#1 v1.5 encoding', function() {
                var messages = ['foo', 'The answer is 42!', _td.SESSION_ID];
                for (var i = 0; i < messages.length; i++) {
                    var result = ns._pkcs1v15_decode(ns._pkcs1v15_encode(messages[i], 256));
                    assert.strictEqual(result, messages[i]);
                }
            });
        });

        describe('_smallrsaencrypt()/_smallrsadecrypt()', function() {
            it('RSA encryption and decryption round trip', function() {
                var messages = ['foo', 'The answer is 42!', _td.SESSION_ID];
                for (var i = 0; i < messages.length; i++) {
                    var cipher = ns._smallrsaencrypt(messages[i], _td.RSA_PUB_KEY);
                    var clear = ns._smallrsadecrypt(cipher, _td.RSA_PRIV_KEY);
                    assert.strictEqual(clear, messages[i]);
                }
            });
        });

        describe('_smallrsaensign()/_smallrsaverify()', function() {
            it('RSA signing and verification round trip', function() {
                var messages = ['foo', 'The answer is 42!', _td.SESSION_ID];
                for (var i = 0; i < messages.length; i++) {
                    var cipher = ns._smallrsasign(messages[i], _td.RSA_PRIV_KEY);
                    var clear = ns._smallrsaverify(cipher, _td.RSA_PUB_KEY);
                    assert.strictEqual(clear, messages[i]);
                }
            });
        });

        describe('_computeSid()', function() {
            it('compute SID', function() {
                var members = ['3', '1', '2', '4', '5'];
                var nonces = ['3333', '1111', '2222', '4444', '5555'];
                var sid = ns._computeSid(members, nonces);
                assert.strictEqual(sid, _td.SESSION_ID);
                // Now in changed order of items.
                members.sort();
                nonces.sort();
                sid = ns._computeSid(members, nonces);
                assert.strictEqual(sid, _td.SESSION_ID);
            });

            it('compute SID (missing members)', function() {
                var members = ['3', '1', null, '4', '5'];
                var nonces = ['3333', '1111', '2222', '4444', '5555'];

                var echo = function(x) {
                    return x;
                };

                sandbox.stub(utils, 'sha256', echo);
                sandbox.stub(djbec, 'bytes2string', echo);
                var sid = ns._computeSid(members, nonces);
                assert.strictEqual(sid, '13451111333344445555');
            });
        });
    });

    describe("SignatureKeyExchangeMember class", function() {
        describe('constructur', function() {
            it('simple constructor', function() {
                new ns.SignatureKeyExchangeMember();
            });
        });

        describe('#commit() method', function() {
            it('start commit chain', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var otherMembers = ['2', '3', '4', '5'];
                var spy = sinon_spy();
                participant.upflow = spy;
                participant.commit(otherMembers);
                sinon_assert.calledOnce(spy);
            });

            it('start commit chain without members', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                assert.throws(function() { participant.commit([]); },
                              'No members to add.');
            });

            it('start commit', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var otherMembers = ['2', '3', '4', '5'];
                var startMessage = participant.commit(otherMembers);
                assert.strictEqual(startMessage.source, '1');
                assert.strictEqual(startMessage.dest, '2');
                assert.strictEqual(startMessage.flow, 'upflow');
                assert.deepEqual(startMessage.members, ['1'].concat(otherMembers));
                assert.lengthOf(startMessage.nonces, 1);
                assert.lengthOf(startMessage.pubKeys, 1);
            });
        });

        describe('#_computeSessionSig() method', function() {
            it('sign something', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.sessionId = _td.SESSION_ID;
                participant.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant.ephemeralPubKey = _td.ED25519_PUB_KEY;
                var signature = participant._computeSessionSig();
                assert.ok(_tu.keyBits(signature, 8) <= 2048);
                assert.ok(_tu.keyBits(signature, 8) >= 2040);
                assert.strictEqual(_tu.keyBits(ns._smallrsaverify(signature, _td.RSA_PUB_KEY), 8), 256);
            });
        });

        describe('#_verifySessionSig() method', function() {
            it('verification fail on invalid member', function() {
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant.sessionId = _td.SESSION_ID;
                participant.ephemeralPubKeys = [];
                for (var i = 0; i < 5; i++) {
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                }
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                assert.throws(function() { participant._verifySessionSig('6', _td.SIGNATURE); },
                              'Member not in participants list.');
            });

            it('verification fail on missing SID', function() {
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                participant.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.ephemeralPubKeys = [];
                for (var i = 0; i < 5; i++) {
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                }
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                assert.throws(function() { participant._verifySessionSig('1', _td.SIGNATURE); },
                              'Session ID not available.');
            });

            it('verification fail on missing ephemeral key', function() {
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant.sessionId = _td.SESSION_ID;
                participant.ephemeralPubKeys = [];
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                assert.throws(function() { participant._verifySessionSig('1', _td.SIGNATURE); },
                              "Member's ephemeral pub key missing.");
            });

            it('verification fail on missing static key', function() {
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant.sessionId = _td.SESSION_ID;
                participant.ephemeralPubKeys = [];
                for (var i = 0; i < 5; i++) {
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                }
                participant.staticPubKeyDir = { 'get': function() { return undefined; }};
                assert.throws(function() { participant._verifySessionSig('1', _td.SIGNATURE); },
                              "Member's static pub key missing.");
            });

            it('verify a signature', function() {
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.sessionId = _td.SESSION_ID;
                participant.ephemeralPubKeys = [];
                participant.nonces = [];
                for (var i = 0; i < 5; i++) {
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                    participant.nonces.push(_td.ED25519_PUB_KEY); // Same form as nonce.

                }
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                assert.strictEqual(participant._verifySessionSig('1', _td.SIGNATURE),
                                   true);
            });

            it('roundtrip sign/verify', function() {
                var participant1 = new ns.SignatureKeyExchangeMember('1');
                participant1.nonce = _td.ED25519_PUB_KEY; // Same form as nonce.
                participant1.sessionId = _td.SESSION_ID;
                participant1.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant1.staticPrivKey = _td.RSA_PRIV_KEY;
                var signature = participant1._computeSessionSig();
                var participant3 = new ns.SignatureKeyExchangeMember('3');
                participant3.sessionId = _td.SESSION_ID;
                participant3.members = ['1', '2', '3', '4', '5'];
                participant3.ephemeralPubKeys = [];
                participant3.nonces = [];
                for (var i = 0; i < 5; i++) {
                    participant3.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                    participant3.nonces.push(_td.ED25519_PUB_KEY);
                }
                participant3.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                assert.strictEqual(participant3._verifySessionSig('1', signature),
                                   true);
            });
        });

        describe('#upflow() method', function() {
            it('upflow duplicates in member list', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['3', '1', '2', '3', '4', '5', '6'];
                var startMessage = new ns.SignatureKeyExchangeMessage();
                startMessage.members = members;
                assert.throws(function() { participant.upflow(startMessage); },
                              'Duplicates in member list detected!');
            });

            it('upflow not in member list', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['2', '3', '4', '5', '6'];
                var startMessage = new ns.SignatureKeyExchangeMessage();
                startMessage.members = members;
                assert.throws(function() { participant.upflow(startMessage); },
                              'Not member of this key exchange!');
            });

            it('upflow, for initiator', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['1', '2', '3', '4', '5'];
                var startMessage = new ns.SignatureKeyExchangeMessage('1', '',
                                                                      'upflow',
                                                                      members);
                var message = participant.upflow(startMessage);
                assert.strictEqual(message.source, '1');
                assert.strictEqual(message.dest, '2');
                assert.deepEqual(message.members, members);
                assert.lengthOf(message.nonces, 1);
                assert.lengthOf(message.pubKeys, 1);
            });

            it('upflow on completed upflow, too many nonces', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['1', '2', '3', '4', '5'];
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'upflow',
                                                                 members);
                message.nonces = ['foo1', 'foo2', 'foo3', 'foo4', 'foo5', 'foo6'];
                message.pubKeys = [];
                for (var i = 0; i < 5; i++) {
                    message.pubKeys.push(_td.ED25519_PUB_KEY);
                }
                assert.throws(function() { participant.upflow(message); },
                              'Too many nonces on ASKE upflow!');
            });

            it('upflow on completed upflow, too many nonces', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['1', '2', '3', '4', '5'];
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'upflow',
                                                                 members);
                message.nonces = ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'];
                message.pubKeys = [];
                for (var i = 0; i < 6; i++) {
                    message.pubKeys.push(_td.ED25519_PUB_KEY);
                }
                assert.throws(function() { participant.upflow(message); },
                              'Too many pub keys on ASKE upflow!');
            });

            it('upflow, for all members', function() {
                var numMembers = 5;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    participants.push(new ns.SignatureKeyExchangeMember(i.toString()));
                }
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'upflow',
                                                                 members);
                for (var i = 0; i < numMembers - 1; i++) {
                    message = participants[i].upflow(message);
                    assert.deepEqual(participants[i].members, members);
                    assert.strictEqual(_tu.keyBits(participants[i].ephemeralPrivKey, 8), 512);
                    assert.strictEqual(_tu.keyBits(participants[i].ephemeralPubKey, 8), 256);
                    assert.strictEqual(message.flow, 'upflow');
                    assert.lengthOf(message.pubKeys, i + 1);
                    assert.strictEqual(_tu.keyBits(message.pubKeys[i], 8), 256);
                    assert.lengthOf(message.nonces, i + 1);
                    assert.strictEqual(_tu.keyBits(message.nonces[i], 8), 256);
                    assert.strictEqual(message.source, members[i]);
                    assert.strictEqual(message.dest, members[i + 1]);
                }

                // The last member behaves differently.
                var lastid = numMembers - 1;
                participants[lastid].staticPrivKey = _td.RSA_PRIV_KEY;
                message = participants[lastid].upflow(message);
                assert.deepEqual(participants[lastid].members, members);
                assert.strictEqual(_tu.keyBits(participants[lastid].ephemeralPrivKey, 8), 512);
                assert.strictEqual(_tu.keyBits(participants[lastid].ephemeralPubKey, 8), 256);
                assert.deepEqual(participants[lastid].authenticatedMembers,
                                 [false, false, false, false, true]);
                assert.strictEqual(message.flow, 'downflow');
                assert.lengthOf(message.pubKeys, numMembers);
                assert.strictEqual(_tu.keyBits(message.pubKeys[lastid], 8), 256);
                assert.lengthOf(message.nonces, numMembers);
                assert.strictEqual(_tu.keyBits(message.nonces[lastid], 8), 256);
                assert.strictEqual(message.source, members[lastid]);
                assert.strictEqual(message.dest, '');
                assert.strictEqual(_tu.keyBits(participants[lastid].sessionId, 8), 256);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) >= 2040);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) <= 2048);
            });

            it('upflow after a join', function() {
                var members = ['1', '2', '3', '4', '5'];
                var startMessage = new ns.SignatureKeyExchangeMessage('3', '',
                                                                             'upflow');
                startMessage.dest = '6';
                startMessage.members = members.concat('6');
                startMessage.nonces = [];
                startMessage.pubKeys = [];
                for (var i = 0; i < members.length; i++) {
                    // Nonces have the same format as the pub key.
                    startMessage.nonces.push(_td.ED25519_PUB_KEY);
                    startMessage.pubKeys.push(_td.ED25519_PUB_KEY);
                }

                var participant = new ns.SignatureKeyExchangeMember('6');
                participant.members = utils.clone(members);
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                var message = participant.upflow(startMessage);
                assert.deepEqual(participant.members, message.members);
                assert.strictEqual(_tu.keyBits(participant.ephemeralPrivKey, 8), 512);
                assert.strictEqual(_tu.keyBits(participant.ephemeralPubKey, 8), 256);
                assert.deepEqual(participant.authenticatedMembers,
                                 [false, false, false, false, false, true]);
                assert.strictEqual(message.source, participant.id);
                assert.strictEqual(message.dest, '');
                assert.strictEqual(message.flow, 'downflow');
                assert.lengthOf(message.pubKeys, 6);
                assert.strictEqual(_tu.keyBits(message.pubKeys[5], 8), 256);
                assert.lengthOf(message.nonces, 6);
                assert.strictEqual(_tu.keyBits(message.nonces[5], 8), 256);
                assert.strictEqual(_tu.keyBits(participant.sessionId, 8), 256);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) >= 2040);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) <= 2048);
            });
        });

        describe('#downflow() method', function() {
            it('downflow duplicates in member list', function() {
                var participant = new ns.SignatureKeyExchangeMember('1');
                var members = ['3', '1', '2', '3', '4', '5', '6'];
                var message = new ns.SignatureKeyExchangeMessage();
                message.members = members;
                assert.throws(function() { participant.downflow(message); },
                              'Duplicates in member list detected!');
            });

            it('downflow, failed authentication', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'downflow',
                                                                 members);
                for (var i = 0; i < 5; i++) {
                    // Nonces have the same format as the pub key.
                    message.nonces.push(_td.ED25519_PUB_KEY);
                    message.pubKeys.push(_td.ED25519_PUB_KEY);
                }
                message.sessionSignature = _td.SIGNATURE;
                sandbox.stub(ns, '_computeSid').returns(
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                assert.throws(function() { participant.downflow(message); },
                              'Authentication of member failed: 1');
            });

            it('downflow, still unacknowledged', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'downflow',
                                                                 members);
                for (var i = 0; i < 5; i++) {
                    // Nonces have the same format as the pub key.
                    message.nonces.push(_td.ED25519_PUB_KEY);
                    message.pubKeys.push(_td.ED25519_PUB_KEY);
                }
                message.sessionSignature = _td.SIGNATURE;
                sandbox.stub(ns, '_computeSid').returns(_td.SESSION_ID);
                var newMessage = participant.downflow(message);
                assert.deepEqual(participant.authenticatedMembers,
                                 [true, false, true, false, false]);
                assert.ok(newMessage !== null);
                assert.ok(_tu.keyBits(newMessage.sessionSignature, 8) <= 2048);
                assert.ok(_tu.keyBits(newMessage.sessionSignature, 8) >= 2040);
            });

            it('downflow, already acknowledged', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                                 'downflow',
                                                                 members);
                participant.sessionId = _td.SESSION_ID.concat();
                participant.authenticatedMembers = [false, false, true, false, true];
                for (var i = 0; i < 5; i++) {
                    // Nonces have the same format as the pub key.
                    message.nonces.push(_td.ED25519_PUB_KEY);
                    message.pubKeys.push(_td.ED25519_PUB_KEY);
                }
                participant.members = utils.clone(message.members);
                participant.nonces = utils.clone(message.nonces);
                participant.ephemeralPubKeys = utils.clone(message.pubKeys);
                participant.sessionId = _td.SESSION_ID.concat();
                message.sessionSignature = _td.SIGNATURE;
                sandbox.stub(ns, '_computeSid').returns(_td.SESSION_ID);
                var newMessage = participant.downflow(message);
                assert.ok(newMessage === null);
                assert.deepEqual(participant.authenticatedMembers,
                                 [true, false, true, false, true]);
            });
        });

        describe('#isSessionAcknowledged() method', function() {
            it('simple tests', function() {
                var tests = [null,
                             [],
                             [false, false, false, false, false],
                             [false, false, true, false, true],
                             [true, true, true, true, true]];
                var expected = [false, false, false, false, true];
                var participant = new ns.SignatureKeyExchangeMember('3');
                for (var i = 0; i++; i < tests.length) {
                    participant.authenticatedMembers = tests[i];
                    assert.strictEqual(participant.isSessionAcknowledged(),
                                       expected[i]);
                }
            });
        });

        describe('#join() method', function() {
            it('join empty member list', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = members;
                assert.throws(function() { participant.join([]); },
                              'No members to add.');
            });

            it('join duplicate member list', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = members;
                assert.throws(function() { participant.join(['2']); },
                              'Duplicates in member list detected!');
            });

            it('join a member', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = utils.clone(members);
                participant.nonces = [];
                participant.ephemeralPubKeys = [];
                for (var i = 0; i < members.length; i++) {
                    // Nonces have the same format as the pub key.
                    participant.nonces.push(_td.ED25519_PUB_KEY);
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                }
                var message = participant.join(['6']);
                assert.deepEqual(message.members, ['1', '2', '3', '4', '5', '6']);
                assert.strictEqual(message.source, '3');
                assert.strictEqual(message.dest, '6');
                assert.strictEqual(message.flow, 'upflow');
                assert.lengthOf(message.nonces, 5);
                assert.lengthOf(message.pubKeys, 5);
            });
        });

        describe('#exclude() method', function() {
            it('exclude empty member list', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = members;
                assert.throws(function() { participant.exclude([]); },
                              'No members to exclude.');
            });

            it('exclude non existing member', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = members;
                assert.throws(function() { participant.exclude(['1', '7']); },
                              'Members list to exclude is not a sub-set of previous members!');
            });

            it('exclude self', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = members;
                assert.throws(function() { participant.exclude(['3', '5']); },
                              'Cannot exclude mysefl.');
            });

            it('exclude members', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.SignatureKeyExchangeMember('3');
                participant.members = utils.clone(members);
                participant.nonces = [];
                participant.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.staticPrivKey = _td.RSA_PRIV_KEY;
                participant.ephemeralPubKeys = [];
                participant.authenticatedMembers = [];
                for (var i = 0; i < members.length; i++) {
                    // Nonces have the same format as the pub key.
                    participant.nonces.push(_td.ED25519_PUB_KEY);
                    participant.ephemeralPubKeys.push(_td.ED25519_PUB_KEY);
                    participant.authenticatedMembers.push(true);
                }
                var message = participant.exclude(['1', '4']);
                assert.deepEqual(participant.members, ['2', '3', '5']);
                assert.lengthOf(participant.nonces, 3);
                assert.lengthOf(participant.ephemeralPubKeys, 3);
                assert.lengthOf(participant.nonces , 3);
                assert.lengthOf(participant.authenticatedMembers , 3);
                assert.deepEqual(participant.oldEphemeralKeys['1'].pub, _td.ED25519_PUB_KEY);
                assert.deepEqual(participant.oldEphemeralKeys['1'].authenticated, true);
                assert.deepEqual(participant.oldEphemeralKeys['4'].pub, _td.ED25519_PUB_KEY);
                assert.deepEqual(participant.oldEphemeralKeys['4'].authenticated, true);
                assert.deepEqual(message.members, ['2', '3', '5']);
                assert.strictEqual(message.source, '3');
                assert.strictEqual(message.dest, '');
                assert.strictEqual(message.flow, 'downflow');
                assert.lengthOf(message.nonces, 3);
                assert.lengthOf(message.pubKeys, 3);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) >= 2040);
                assert.ok(_tu.keyBits(message.sessionSignature, 8) <= 2048);
            });
        });

        describe('whole ASKE', function() {
            it('whole flow for 5 members, 2 joining, 2 others leaving', function() {
                var numMembers = 5;
                var initiator = 0;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    var newMember = new ns.SignatureKeyExchangeMember(i.toString());
                    newMember.staticPrivKey = _td.RSA_PRIV_KEY;
                    newMember.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                    participants.push(newMember);
                }
                var otherMembers = [];
                for (var i = 2; i <= numMembers; i++) {
                    otherMembers.push(i.toString());
                }
                // ASKE commit.
                var message = participants[initiator].commit(otherMembers);

                // ASKE upflow.
                while (message.flow === 'upflow') {
                    if (message.dest !== '') {
                        var nextId = message.members.indexOf(message.dest);
                        message = participants[nextId].upflow(message);
                    } else {
                        assert.ok(false,
                                  "This shouldn't happen, something's seriously dodgy!");
                    }
                }

                // ASKE downflow for all.
                var sid = null;
                var nextMessages = [];
                while (message !== undefined) {
                    for (var i = 0; i < numMembers; i++) {
                        var participant = participants[i];
                        var nextMessage = participant.downflow(message);
                        if (nextMessage !== null) {
                            nextMessages.push(nextMessage);
                        }
                        assert.strictEqual(participant.id, members[i]);
                        assert.deepEqual(participant.members, members);
                        if (!sid) {
                            sid = participant.sessionId;
                        } else {
                            assert.strictEqual(participant.sessionId, sid);
                        }
                    }
                    message = nextMessages.shift();
                }
                for (var i = 0; i < participants.length; i++) {
                    assert.ok(participants[i].isSessionAcknowledged());
                }

                // Join two new guys.
                var newMembers = ['6', '7'];
                members = members.concat(newMembers);
                for (var i = 0; i < newMembers.length; i++) {
                    var newMember = new ns.SignatureKeyExchangeMember(newMembers[i]);
                    newMember.staticPubKeyDir = _td.STATIC_PUB_KEY_DIR;
                    newMember.staticPrivKey = _td.RSA_PRIV_KEY;
                    participants.push(newMember);
                }

                // '4' starts upflow for join.
                message = participants[3].join(newMembers);
                // Upflow for join.
                while (message.flow === 'upflow') {
                    if (message.dest !== '') {
                        var nextId = message.members.indexOf(message.dest);
                        message = participants[nextId].upflow(message);
                    } else {
                        assert.ok(false,
                                  "This shouldn't happen, something's seriously dodgy!");
                    }
                }

                // Downflow for join.
                sid = null;
                nextMessages = [];
                while (message !== undefined) {
                    for (var i = 0; i < members.length; i++) {
                        var participant = participants[i];
                        var nextMessage = participant.downflow(message);
                        if (nextMessage !== null) {
                            nextMessages.push(nextMessage);
                        }
                        assert.strictEqual(participant.id, members[i]);
                        assert.deepEqual(participant.members, members);
                        if (!sid) {
                            sid = participant.sessionId;
                        } else {
                            assert.strictEqual(participant.sessionId, sid);
                        }
                    }
                    message = nextMessages.shift();
                }
                for (var i = 0; i < participants.length; i++) {
                    assert.ok(participants[i].isSessionAcknowledged());
                }

                // '3' excludes two members.
                var toExclude = ['1', '4'];
                members.splice(members.indexOf('1'), 1);
                members.splice(members.indexOf('4'), 1);
                message = participants[2].exclude(toExclude);

                // Downflow for exclude.
                sid = null;
                nextMessages = [];
                while (message !== undefined) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        var nextMessage = participant.downflow(message);
                        if (nextMessage !== null) {
                            nextMessages.push(nextMessage);
                        }
                        assert.deepEqual(participant.members, members);
                        if (!sid) {
                            sid = participant.sessionId;
                        } else {
                            assert.strictEqual(participant.sessionId, sid);
                        }
                    }
                    message = nextMessages.shift();
                }
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    assert.ok(participant.isSessionAcknowledged());
                }
            });
        });
    });

    //var bytes = djbec.string2bytes(message.sessionSignature);
    //var hex = djbec.bytes2hex(bytes);
    //assert.deepEqual(bytes, utils.hex2bytearray(hex));
});
