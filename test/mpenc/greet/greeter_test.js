/**
 * @fileOverview
 * Test of the `mpenc/greet/greeter` module.
 */

/*
 * Created: 2 Mar 2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/greet/greeter",
    "mpenc/helper/utils",
    "mpenc/codec",
    "asmcrypto",
    "jodid25519",
    "megalogger",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
    "sinon/stub",
], function(ns, utils, codec, asmCrypto, jodid25519, MegaLogger,
            chai, sinon_assert, sinon_sandbox, sinon_spy, stub) {
    "use strict";

    var assert = chai.assert;

    function _echo(x) {
        return x;
    }


    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });


    describe("encodeGreetMessage()", function() {
        it('upflow message', function() {
            sandbox.stub(codec, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeGreetMessage(_td.UPFLOW_MESSAGE_CONTENT,
                                                 _td.ED25519_PRIV_KEY,
                                                 _td.ED25519_PUB_KEY);
            assert.lengthOf(result, 61);
        });

        it('upflow message binary', function() {
            var result = ns.encodeGreetMessage(_td.UPFLOW_MESSAGE_CONTENT,
                                                 _td.ED25519_PRIV_KEY,
                                                 _td.ED25519_PUB_KEY);
            assert.strictEqual(result, _td.UPFLOW_MESSAGE_STRING);
        });

        it('downflow message for quit', function() {
            sandbox.stub(codec, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeGreetMessage(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                 _td.ED25519_PRIV_KEY,
                                                 _td.ED25519_PUB_KEY);
            assert.lengthOf(result, 25);
        });

        it('downflow message for quit binary', function() {
            var result = ns.encodeGreetMessage(_td.DOWNFLOW_MESSAGE_CONTENT,
                                                 _td.ED25519_PRIV_KEY,
                                                 _td.ED25519_PUB_KEY);
            assert.strictEqual(result, _td.DOWNFLOW_MESSAGE_STRING);
        });

        it('null message', function() {
            assert.strictEqual(ns.encodeGreetMessage(null,
                               _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY),
                               null);
            assert.strictEqual(ns.encodeGreetMessage(undefined,
                               _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY),
                               null);
        });
    });

    describe("decodeGreetMessage()", function() {
        it('upflow message', function() {
            var result = ns.decodeGreetMessage(_td.UPFLOW_MESSAGE_STRING,
                                                 _td.ED25519_PUB_KEY);
            assert.strictEqual(result.source, _td.UPFLOW_MESSAGE_CONTENT.source);
            assert.strictEqual(result.dest, _td.UPFLOW_MESSAGE_CONTENT.dest);
            assert.strictEqual(result.greetType, _td.UPFLOW_MESSAGE_CONTENT.greetType);
            assert.deepEqual(result.members, _td.UPFLOW_MESSAGE_CONTENT.members);
            assert.deepEqual(result.intKeys, _td.UPFLOW_MESSAGE_CONTENT.intKeys);
            assert.deepEqual(result.nonces, _td.UPFLOW_MESSAGE_CONTENT.nonces);
            assert.deepEqual(result.pubKeys, _td.UPFLOW_MESSAGE_CONTENT.pubKeys);
            assert.strictEqual(result.sessionSignature, _td.UPFLOW_MESSAGE_CONTENT.sessionSignature);
        });

        it('upflow message, debug on', function() {
            sandbox.stub(MegaLogger._logRegistry.greeter, '_log');
            ns.decodeGreetMessage(_td.UPFLOW_MESSAGE_STRING,
                                    _td.ED25519_PUB_KEY);
            var log = MegaLogger._logRegistry.greeter._log.getCall(0).args;
            assert.deepEqual(log, [0, ['mpENC decoded message debug: ',
                                       ['messageSignature: 3BaWQ/ZIomYPke7HYr0i2afjPh24Ym+3QGbYuowS6weB396AuzPas2YSMnVgX6fR4Yfu1TAfInoRmJaEVgThAg==',
                                        'protocol: 1',
                                        'greetType: 0x9c (INIT_INITIATOR_UP)',
                                        'from: 1', 'to: 2',
                                        'member: 1', 'member: 2', 'member: 3', 'member: 4', 'member: 5', 'member: 6',
                                        'intKey: ', 'intKey: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                        'nonce: hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                                        'pubKey: 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=']]]);
        });

        it('downflow message for quit', function() {
            var result = ns.decodeGreetMessage(_td.DOWNFLOW_MESSAGE_STRING,
                                                 _td.ED25519_PUB_KEY);
            assert.strictEqual(result.source, _td.DOWNFLOW_MESSAGE_CONTENT.source);
            assert.strictEqual(result.dest, _td.DOWNFLOW_MESSAGE_CONTENT.dest);
            assert.strictEqual(result.greetType, _td.DOWNFLOW_MESSAGE_CONTENT.greetType);
            assert.strictEqual(result.signingKey, _td.DOWNFLOW_MESSAGE_CONTENT.signingKey);
        });

        it('wrong protocol version', function() {
            var message = _td.UPFLOW_MESSAGE_STRING.substring(68, 72)
                        + String.fromCharCode(77)
                        + _td.UPFLOW_MESSAGE_STRING.substring(73);
            assert.throws(function() { ns.decodeGreetMessage(message, _td.ED25519_PUB_KEY); },
                          'decode failed; expected PROTOCOL_VERSION');
        });
    });


    describe("GreetWrapper class", function() {
        describe('constructor', function() {
            it('fails for missing params', function() {
                assert.throws(function() { new ns.GreetWrapper('42', _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY); },
                              "Constructor call missing required parameters.");
            });

            it('just make an instance', function() {
                var participant = new ns.GreetWrapper('42',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                assert.strictEqual(participant.id, '42');
                assert.strictEqual(participant.privKey, _td.ED25519_PRIV_KEY);
                assert.strictEqual(participant.pubKey, _td.ED25519_PUB_KEY);
                assert.ok(participant.staticPubKeyDir.get('3'));
                assert.deepEqual(participant.askeMember.staticPrivKey, _td.ED25519_PRIV_KEY);
                assert.ok(participant.askeMember.staticPubKeyDir);
                assert.ok(participant.cliquesMember);
                assert.strictEqual(participant.state, ns.STATE.NULL);
            });
        });

        describe('#_mergeMessages() method', function() {
            it('fail for mismatching senders', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var cliquesMessage = { source: '1', dest: '2', agreement: 'ika', flow: 'up',
                                       members: ['1', '2', '3', '4', '5', '6'], intKeys: null };
                var askeMessage = { source: '2', dest: '2', flow: 'up',
                                    members: ['1', '2', '3', '4', '5', '6'],
                                    nonces: null, pubKeys: null, sessionSignature: null };
                assert.throws(function() { participant._mergeMessages(cliquesMessage, askeMessage); },
                              "Message source mismatch, this shouldn't happen.");
            });

            it('fail for mismatching receivers', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var cliquesMessage = { source: '1', dest: '2', agreement: 'ika', flow: 'up',
                                       members: ['1', '2', '3', '4', '5', '6'], intKeys: null };
                var askeMessage = { source: '1', dest: '', flow: 'up',
                                    members: ['1', '2', '3', '4', '5', '6'],
                                    nonces: null, pubKeys: null, sessionSignature: null };
                assert.throws(function() { participant._mergeMessages(cliquesMessage, askeMessage); },
                              "Message destination mismatch, this shouldn't happen.");
            });

            it('merge the messages', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var cliquesMessage = { source: '1', dest: '2', agreement: 'ika', flow: 'up',
                                       members: ['1', '2', '3', '4', '5', '6'], intKeys: null };
                var askeMessage = { source: '1', dest: '2', flow: 'up',
                                    members: ['1', '2', '3', '4', '5', '6'],
                                    nonces: null, pubKeys: null, sessionSignature: null };
                var message = participant._mergeMessages(cliquesMessage, askeMessage);
                assert.strictEqual(message.source, cliquesMessage.source);
                assert.strictEqual(message.dest, cliquesMessage.dest);
                assert.deepEqual(message.members, cliquesMessage.members);
                assert.deepEqual(message.intKeys, cliquesMessage.intKeys);
                assert.deepEqual(message.nonces, askeMessage.nonces);
                assert.deepEqual(message.pubKeys, askeMessage.pubKeys);
                assert.strictEqual(message.sessionSignature, askeMessage.sessionSignature);
            });

            it('merge the messages for ASKE only', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var askeMessage = { source: '3', dest: '', flow: 'down',
                                    members: ['1', '2', '3', '4', '5', '6'],
                                    nonces: null, pubKeys: null, sessionSignature: null,
                                    signingKey: null };
                var message = participant._mergeMessages(null, askeMessage);
                assert.strictEqual(message.source, '1');
                assert.strictEqual(message.dest, askeMessage.dest);
                assert.deepEqual(message.members, askeMessage.members);
                assert.deepEqual(message.intKeys, null);
                assert.deepEqual(message.nonces, askeMessage.nonces);
                assert.deepEqual(message.pubKeys, askeMessage.pubKeys);
                assert.strictEqual(message.sessionSignature, askeMessage.sessionSignature);
                assert.strictEqual(message.signingKey, null);
            });

            it('merge the messages for CLIQUES only', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var cliquesMessage = { source: '1', dest: '', agreement: 'aka', flow: 'down',
                                       members: ['1', '2', '3', '4', '5'], intKeys: null };
                var message = participant._mergeMessages(cliquesMessage, null);
                assert.strictEqual(message.source, '1');
                assert.strictEqual(message.dest, cliquesMessage.dest);
                assert.deepEqual(message.members, cliquesMessage.members);
                assert.deepEqual(message.intKeys, cliquesMessage.intKeys);
            });

            it('merge the messages for final case (no messages)', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var message = participant._mergeMessages(null, undefined);
                assert.strictEqual(message, null);
            });
        });

        describe('#_getCliquesMessage() method', function() {
            it('the vanilla ika case', function() {
                var message = {
                    source: '1',
                    dest: '2',
                    greetType: codec.GREET_TYPE.INIT_INITIATOR_UP,
                    members: ['1', '2', '3', '4', '5', '6'],
                    intKeys: null,
                    nonces: null,
                    pubKeys: null,
                    sessionSignature: null
                };

                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var compare = { source: '1', dest: '2', agreement: 'ika', flow: 'up',
                                members: ['1', '2', '3', '4', '5', '6'], intKeys: [] };
                var cliquesMessage = participant._getCliquesMessage(
                        new codec.ProtocolMessage(message));
                assert.strictEqual(cliquesMessage.source, compare.source);
                assert.strictEqual(cliquesMessage.dest, compare.dest);
                assert.strictEqual(cliquesMessage.flow, compare.flow);
                assert.strictEqual(cliquesMessage.agreement, compare.agreement);
                assert.deepEqual(cliquesMessage.members, compare.members);
                assert.deepEqual(cliquesMessage.intKeys, compare.intKeys);
            });
        });

        describe('#_getAskeMessage() method', function() {
            it('the vanilla initial case', function() {
                var message = {
                    source: '1',
                    dest: '2',
                    greetType: codec.GREET_TYPE.INIT_INITIATOR_UP,
                    members: ['1', '2', '3', '4', '5', '6'],
                    intKeys: null,
                    nonces: null,
                    pubKeys: null,
                    sessionSignature: null,
                    signingKey: null,
                };

                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var compare = { source: '1', dest: '2', flow: 'up',
                                members: ['1', '2', '3', '4', '5', '6'],
                                nonces: [], pubKeys: [], sessionSignature: null,
                                signingKey: null };
                var askeMessage = participant._getAskeMessage(
                        new codec.ProtocolMessage(message));
                assert.strictEqual(askeMessage.source, compare.source);
                assert.strictEqual(askeMessage.dest, compare.dest);
                assert.strictEqual(askeMessage.flow, compare.flow);
                assert.deepEqual(askeMessage.members, compare.members);
                assert.deepEqual(askeMessage.nonces, compare.nonces);
                assert.deepEqual(askeMessage.pubKeys, compare.pubKeys);
                assert.deepEqual(askeMessage.sessionSignature, compare.sessionSignature);
                assert.strictEqual(askeMessage.signingKey, compare.signingKey);
            });

            it('auxiliary downflow case for a quit', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var compare = { source: '1', dest: '', flow: 'down',
                                signingKey: _td.ED25519_PRIV_KEY };
                var askeMessage = participant._getAskeMessage(
                        new codec.ProtocolMessage(_td.DOWNFLOW_MESSAGE_CONTENT));
                assert.strictEqual(askeMessage.source, compare.source);
                assert.strictEqual(askeMessage.dest, compare.dest);
                assert.strictEqual(askeMessage.flow, compare.flow);
                assert.strictEqual(askeMessage.signingKey, compare.signingKey);
            });
        });

        describe('#start() method', function() {
            it('start/initiate a group session', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                sandbox.spy(participant.cliquesMember, 'ika');
                sandbox.spy(participant.askeMember, 'commit');
                sandbox.stub(ns, 'encodeGreetMessage', stub());
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage());
                var otherMembers = ['2', '3', '4', '5', '6'];
                participant.subscribeSend(function(){}); // bypass no-subscriber warning
                participant.start(otherMembers);
                sinon_assert.calledOnce(participant.cliquesMember.ika);
                sinon_assert.calledOnce(participant.askeMember.commit);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(ns.encodeGreetMessage);
                assert.strictEqual(ns.encodeGreetMessage.getCall(0).args[0].greetType, codec.GREET_TYPE.INIT_INITIATOR_UP);
            });
        });

        describe('#inclnude() method', function() {
            it('include empty member list', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.READY;
                assert.throws(function() { participant.include([]); },
                              'No members to add.');
            });

            it('add members to group', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.cliquesMember.akaJoin = sinon_spy();
                participant.askeMember.join = sinon_spy();
                participant.state = ns.STATE.READY;
                sandbox.stub(ns, 'encodeGreetMessage', stub());
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage());
                var otherMembers = ['6', '7'];
                participant.subscribeSend(function(){}); // bypass no-subscriber warning
                participant.include(otherMembers);
                sinon_assert.calledOnce(participant.cliquesMember.akaJoin);
                sinon_assert.calledOnce(participant.askeMember.join);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(ns.encodeGreetMessage);
                assert.strictEqual(ns.encodeGreetMessage.getCall(0).args[0].greetType, codec.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP);
            });
        });

        describe('#exclude() method', function() {
            it('exclude empty member list', function() {
                var participant = new ns.GreetWrapper('3',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.READY;
                assert.throws(function() { participant.exclude([]); },
                              'No members to exclude.');
            });

            it('exclude self', function() {
                var participant = new ns.GreetWrapper('3',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.READY;
                assert.throws(function() { participant.exclude(['3', '5']); },
                              'Cannot exclude mysefl.');
            });

            it('exclude members', function() {
                var participant = new ns.GreetWrapper('3',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.cliquesMember.akaExclude = sinon_spy();
                participant.askeMember.exclude = sinon_spy();
                participant.state = ns.STATE.READY;
                sandbox.stub(ns, 'encodeGreetMessage', stub());
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage());
                participant.subscribeSend(function(){}); // bypass no-subscriber warning
                participant.exclude(['1', '4']);
                sinon_assert.calledOnce(participant.cliquesMember.akaExclude);
                sinon_assert.calledOnce(participant.askeMember.exclude);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(ns.encodeGreetMessage);
                assert.strictEqual(ns.encodeGreetMessage.getCall(0).args[0].greetType, codec.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN);
            });
        });

        describe('#quit() method', function() {
            it('simple test', function() {
                var participant = new ns.GreetWrapper('peter@genesis.co.uk/android4711',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                sandbox.spy(participant.askeMember, 'quit');
                sandbox.stub(ns, 'encodeGreetMessage', stub());
                sandbox.stub(participant.cliquesMember, 'akaQuit');
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage());
                participant.subscribeSend(function(){}); // bypass no-subscriber warning
                participant.quit();
                sinon_assert.calledOnce(participant.askeMember.quit);
                sinon_assert.calledOnce(participant.cliquesMember.akaQuit);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(ns.encodeGreetMessage);
                assert.strictEqual(ns.encodeGreetMessage.getCall(0).args[0].greetType, codec.GREET_TYPE.QUIT_DOWN);
            });
        });

        describe('#refresh() method', function() {
            it('refresh own private key using aka', function() {
                var participant = new ns.GreetWrapper('3',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant._mergeMessages = stub().returns(new codec.ProtocolMessage());
                participant.cliquesMember.akaRefresh = sinon_spy();
                sandbox.stub(ns, 'encodeGreetMessage', stub());
                participant.state = ns.STATE.READY;
                participant.subscribeSend(function(){}); // bypass no-subscriber warning
                participant.refresh();
                sinon_assert.calledOnce(participant.cliquesMember.akaRefresh);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(ns.encodeGreetMessage);
                assert.strictEqual(ns.encodeGreetMessage.getCall(0).args[0].greetType, codec.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN);
            });
        });

        describe('#_processMessage() method', function() {
            it('processing for an upflow message', function() {
                var message = { source: '1', dest: '2',
                                greetType: codec.GREET_TYPE.INIT_INITIATOR_UP,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [null, []], debugKeys: [null, '1*G'],
                                nonces: ['foo'], pubKeys: ['foo'],
                                sessionSignature: null };
                var compare = { source: '2', dest: '3',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_UP,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], []], debugKeys: ['2*G', '1*G', '2*1*G'],
                                nonces: ['foo', 'bar'], pubKeys: ['foo', 'bar'],
                                sessionSignature: null };
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(result.newState, ns.STATE.INIT_UPFLOW);
                var output = result.decodedMessage;
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.greetType, compare.greetType);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.deepEqual(output.debugKeys, compare.debugKeys);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.strictEqual(output.sessionSignature, compare.sessionSignature);
            });

            it('processing for last upflow message', function() {
                var message = { source: '4', dest: '5',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_UP,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['', '', '', '', ''],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4'],
                                sessionSignature: null };
                var compare = { source: '5', dest: '',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.GreetWrapper('5',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.NULL;
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(result.newState, ns.STATE.INIT_DOWNFLOW);
                var output = result.decodedMessage;
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.greetType, compare.greetType);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.ok(output.sessionSignature);
            });

            it('processing for recovery upflow message', function() {
                var message = { source: '4', dest: '5',
                                greetType: codec.GREET_TYPE.RECOVER_INIT_PARTICIPANT_UP,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['', '', '', '', ''],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4'],
                                sessionSignature: null };
                var compare = { source: '5', dest: '',
                                greetType: codec.GREET_TYPE.RECOVER_INIT_PARTICIPANT_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.GreetWrapper('5',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.AUX_DOWNFLOW;
                participant.askeMember.authenticatedMembers= [true, true, true, true, true]
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(participant.recovering, true);
                assert.deepEqual(participant.askeMember.authenticatedMembers, [false, false, false, false, true]);
                assert.strictEqual(result.newState, ns.STATE.INIT_DOWNFLOW);
                var output = result.decodedMessage;
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.greetType, compare.greetType);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.ok(output.sessionSignature);
            });

            it('processing for a downflow message', function() {
                var message = { source: '5', dest: '',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['5*4*3*2*G', '5*4*3*1*G', '5*4*2*1*G',
                                            '5*3*2*1*G', '4*3*2*1*G'],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.INIT_UPFLOW;
                sandbox.spy(participant.cliquesMember, 'upflow');
                sandbox.stub(participant.cliquesMember, 'downflow');
                sandbox.spy(participant.askeMember, 'upflow');
                sandbox.stub(participant.askeMember, 'downflow');
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage({dest: ''}));
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(result.newState, ns.STATE.INIT_DOWNFLOW);
                assert.strictEqual(participant.cliquesMember.upflow.callCount, 0);
                assert.strictEqual(participant.askeMember.upflow.callCount, 0);
                sinon_assert.calledOnce(participant.cliquesMember.downflow);
                sinon_assert.calledOnce(participant.askeMember.downflow);
                sinon_assert.calledOnce(participant._mergeMessages);
            });

            it('processing for a downflow message with invalid session auth', function() {
                var message = { source: '5', dest: '',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['5*4*3*2*G', '5*4*3*1*G', '5*4*2*1*G',
                                            '5*3*2*1*G', '4*3*2*1*G'],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = ns.STATE.INIT_UPFLOW;
                sandbox.stub(participant.cliquesMember, 'downflow');
                sandbox.stub(participant.askeMember, 'downflow').throws(new Error('Session authentication by member 5 failed.'));
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage({ source: participant.id,
                                                                                             dest: '',
                                                                                             flow: 'down',
                                                                                             signingKey: _td.ED25519_PRIV_KEY }));
                assert.throws(function() { participant._processMessage(new codec.ProtocolMessage(message)); },
                              'Session authentication by member 5 failed.');
            });

            it('processing for a downflow message after CLIQUES finish', function() {
                var message = { source: '5', dest: '',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_CONFIRM_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [], debugKeys: [],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.askeMember.members = ['1', '2', '3', '4', '5'];
                participant.askeMember.ephemeralPubKeys = ['1', '2', '3', '4', '5'];
                participant.state = ns.STATE.INIT_DOWNFLOW;
                participant.cliquesMember.groupKey = "bar";
                sandbox.spy(participant.cliquesMember, 'upflow');
                sandbox.stub(participant.cliquesMember, 'downflow');
                sandbox.spy(participant.askeMember, 'upflow');
                sandbox.stub(participant.askeMember, 'downflow');
                sandbox.stub(participant, '_mergeMessages').returns(new codec.ProtocolMessage({dest: ''}));
                sandbox.stub(participant.askeMember, 'isSessionAcknowledged').returns(true);
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(result.newState, ns.STATE.READY);
                assert.strictEqual(participant.cliquesMember.upflow.callCount, 0);
                assert.strictEqual(participant.askeMember.upflow.callCount, 0);
                assert.strictEqual(participant.cliquesMember.downflow.callCount, 0);
                sinon_assert.calledOnce(participant._mergeMessages);
                sinon_assert.calledOnce(participant.askeMember.downflow);
                sinon_assert.calledOnce(participant.askeMember.isSessionAcknowledged);
            });

            it('processing for a downflow quit message', function() {
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.READY;
                participant.askeMember.ephemeralPubKeys = {'1': _td.ED25519_PUB_KEY};
                var result = participant._processMessage(
                        new codec.ProtocolMessage(_td.DOWNFLOW_MESSAGE_CONTENT));
                assert.strictEqual(participant.askeMember.oldEphemeralKeys['1'].priv, _td.ED25519_PRIV_KEY);
                assert.strictEqual(participant.askeMember.oldEphemeralKeys['1'].pub, _td.ED25519_PUB_KEY);
            });

            it('processing for a downflow message after a quit', function() {
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                participant.state = ns.STATE.QUIT;
                var result = participant._processMessage(
                        new codec.ProtocolMessage(_td.DOWNFLOW_MESSAGE_CONTENT));
                assert.strictEqual(result, null);
                assert.strictEqual(participant.state, ns.STATE.QUIT);
            });

            it('processing for a downflow without me in it', function() {
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var message = { source: '1', dest: '',
                                greetType: codec.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN,
                                members: ['1', '3', '4', '5'] };
                participant.state = ns.STATE.READY;
                var result = participant._processMessage(
                        new codec.ProtocolMessage(message));
                assert.deepEqual(result,
                                 { decodedMessage: null, newState: ns.STATE.QUIT });
            });

            it('processing for an upflow message not for me', function() {
                var participant = new ns.GreetWrapper('2',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var message = { source: '3', dest: '4',
                                greetType: codec.GREET_TYPE.INIT_PARTICIPANT_UP,
                                members: ['1', '3', '2', '4', '5'] };
                participant.state = ns.STATE.INIT_UPFLOW;
                var result = participant._processMessage(
                        new codec.ProtocolMessage(message));
                assert.strictEqual(result, null);
            });

            it('processing for a downflow from me', function() {
                var participant = new ns.GreetWrapper('1',
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY,
                                                      _td.STATIC_PUB_KEY_DIR);
                var message = { source: '1', dest: '',
                                greetType: codec.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN,
                                members: ['1', '3', '4', '5'] };
                participant.state = ns.STATE.AUX_DOWNFLOW;
                var result = participant._processMessage(new codec.ProtocolMessage(message));
                assert.strictEqual(result, null);
            });
        });
    });

});
