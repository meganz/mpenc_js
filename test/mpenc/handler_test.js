/**
 * @fileOverview
 * Test of the `mpenc/handler` module.
 */

/*
 * Created: 27 Feb 2014-2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/handler",
    "mpenc/helper/utils",
    "mpenc/codec",
    "mpenc/version",
    "mpenc/greet/keystore",
    "mpenc/greet/greeter",
    "asmcrypto",
    "jodid25519",
    "megalogger",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
    "sinon/stub",
], function(ns, utils, codec, version, keystore, greeter, asmCrypto, jodid25519, MegaLogger,
            chai, sinon_assert, sinon_sandbox, sinon_spy, stub) {
    "use strict";

    var assert = chai.assert;

    function _echo(x) {
        return x;
    }

    function _dummySessionStore() {
        var store = new keystore.KeyStore('dummy', stub().returns(1000));
        store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
        store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
        store.pubKeyMap = utils.clone(_td.SESSION_KEY_STORE.pubKeyMap);
        return store;
    }


    // set test data
    _td.DATA_MESSAGE_CONTENT.protocol = version.PROTOCOL_VERSION;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        sandbox.stub(MegaLogger._logRegistry.handler, '_log');
        sandbox.stub(MegaLogger._logRegistry.assert.options, 'isEnabled', false);
    });

    afterEach(function() {
        sandbox.restore();
    });

    function _stripProtoFromMessage(message) {
        var _PROTO_STRING = '?mpENC:';
        if (!message) {
            return null;
        }
        return atob(message.substring(_PROTO_STRING.length, message.length - 1));
    }

    function _getPayload(message, senderParticipant) {
        if (message && senderParticipant) {
            var content = codec.categoriseMessage(_stripProtoFromMessage(message.message)).content;
            var sessionID = senderParticipant.sessionKeyStore.sessionIDs[0];
            var groupKey = sessionID
                         ? senderParticipant.sessionKeyStore.sessions[sessionID].groupKeys[0]
                         : undefined;
            return codec.decodeMessageContent(content, senderParticipant.greet.askeMember.ephemeralPubKey,
                                              sessionID, groupKey);
        } else {
            return null;
        }
    }

    function _getSender(message, participants, members) {
        if (!message) {
            return null;
        }
        var index = members.indexOf(message.from);
        return participants[index];
    }

    describe("DecryptTrialTarget class", function() {
        describe('#paramId method', function() {
            it('simple ID of message', function() {
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: 'foo' }
                );
                sandbox.stub(utils, 'sha256', _echo);
                var message = { from: 'somebody',
                                to: 'someone else',
                                message: _td.DATA_MESSAGE_STRING };
                var target = new ns.DecryptTrialTarget(stub(), [], 42);
                assert.strictEqual(target.paramId(message), 'foo');
                assert.strictEqual(codec.categoriseMessage.callCount, 1);
                assert.strictEqual(utils.sha256.callCount, 1);
            });
        });

        describe('#maxSize method', function() {
            it('simple ID of message', function() {
                var target = new ns.DecryptTrialTarget(stub(), [], 42);
                assert.strictEqual(target.maxSize(), 42);
            });
        });

        describe('#tryMe', function() {
            it('succeeding try func, not pending', function() {
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                var sessionKeyStore = _dummySessionStore();
                var message = { from: 'Moe',
                                to: '',
                                message: _td.DATA_MESSAGE_PAYLOAD };
                var target = new ns.DecryptTrialTarget(sessionKeyStore, [], 42);
                var result = target.tryMe(false, message);
                assert.strictEqual(result, true);
                assert.lengthOf(target._outQueue, 1);
            });

            it('succeeding try func, not pending, previous group key', function() {
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                sandbox.spy(codec, 'inspectMessageContent');
                sandbox.spy(codec, 'decodeMessageContent');
                sandbox.spy(codec, 'verifyMessageSignature');
                var sessionKeyStore = _dummySessionStore();
                sessionKeyStore.sessions[_td.SESSION_ID].groupKeys.unshift(atob('Dw4NDAsKCQgHBgUEAwIBAA=='));
                var message = { from: 'Moe',
                                to: '',
                                message: _td.DATA_MESSAGE_PAYLOAD };
                var target = new ns.DecryptTrialTarget(sessionKeyStore, [], 42);
                var result = target.tryMe(false, message);
                assert.strictEqual(result, true);
                assert.lengthOf(target._outQueue, 1);
                assert.strictEqual(codec.inspectMessageContent.callCount, 1);
                assert.strictEqual(codec.decodeMessageContent.callCount, 1);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 1);
            });

            it('succeeding try func, not pending, previous session', function() {
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                sandbox.spy(codec, 'inspectMessageContent');
                sandbox.spy(codec, 'decodeMessageContent');
                sandbox.spy(codec, 'verifyMessageSignature');
                var sessionKeyStore = _dummySessionStore();
                sessionKeyStore.sessionIDs.unshift('foo');
                sessionKeyStore.sessions['foo'] = utils.clone(sessionKeyStore.sessions[_td.SESSION_ID]);
                sessionKeyStore.sessions['foo'].groupKeys[0] = atob('Dw4NDAsKCQgHBgUEAwIBAA==');
                var message = { from: 'Moe',
                                to: '',
                                message: _td.DATA_MESSAGE_PAYLOAD };
                var target = new ns.DecryptTrialTarget(sessionKeyStore, [], 42);
                var result = target.tryMe(false, message);
                assert.strictEqual(result, true);
                assert.lengthOf(target._outQueue, 1);
                assert.strictEqual(codec.inspectMessageContent.callCount, 1);
                assert.strictEqual(codec.decodeMessageContent.callCount, 1);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 1);
            });

            it('succeeding try func, not pending, hint collision', function() {
                var collidingKey = 'XqtAZ4L9eY4qFdf6XsfgsQ==';
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                sandbox.spy(codec, 'inspectMessageContent');
                sandbox.spy(codec, 'decodeMessageContent');
                sandbox.spy(codec, 'verifyMessageSignature');
                var sessionKeyStore = _dummySessionStore();
                sessionKeyStore.sessions[_td.SESSION_ID].groupKeys.unshift(atob(collidingKey));
                var message = { from: 'Moe',
                                to: '',
                                message: _td.DATA_MESSAGE_PAYLOAD };
                var target = new ns.DecryptTrialTarget(sessionKeyStore, [], 42);
                var result = target.tryMe(false, message);
                assert.strictEqual(result, true);
                assert.lengthOf(target._outQueue, 1);
                assert.strictEqual(codec.inspectMessageContent.callCount, 1);
                assert.strictEqual(codec.decodeMessageContent.callCount, 1);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 2);
            });
        });
    });

    describe("ProtocolHandler class", function() {
        describe('constructor', function() {
            it('fails for missing params', function() {
                assert.throws(function() { new ns.ProtocolHandler('42', _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY,
                                                                  _td.STATIC_PUB_KEY_DIR); },
                              "Constructor call missing required parameters.");
            });

            it('just make an instance', function() {
                var handler = new ns.ProtocolHandler('42', 'HHGTTG',
                                                     _td.ED25519_PRIV_KEY,
                                                     _td.ED25519_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
                assert.strictEqual(handler.id, '42');
                assert.strictEqual(handler.name, 'HHGTTG');
                assert.ok(handler.staticPubKeyDir.get('3'));
                assert.deepEqual(handler.greet.askeMember.staticPrivKey, _td.ED25519_PRIV_KEY);
                assert.ok(handler.greet.askeMember.staticPubKeyDir);
                assert.ok(handler.greet.cliquesMember);
                assert.ok(handler.sessionKeyStore);
            });
        });

        describe('#start() method', function() {
            it('start/initiate a group session', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: "I'm puttin' the band back together!",
                               dest: 'elwood@blues.org/ios1234'};
                sandbox.stub(codec, 'encodeMessage', _echo);
                sandbox.stub(participant, '_start').returns(message);
                participant.start(['elwood@blues.org/ios1234']);
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._start);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'jake@blues.org/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'elwood@blues.org/ios1234');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.INIT_UPFLOW);
            });

            it('illegal state transition', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var illegalStates = [greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.INIT_DOWNFLOW,
                                     greeter.STATE.READY,
                                     greeter.STATE.AUX_UPFLOW,
                                     greeter.STATE.AUX_DOWNFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.state = illegalStates[i];
                    assert.throws(function() { participant.start(); },
                                  'start() can only be called from an uninitialised state.');
                }
            });
        });

        describe('#join() method', function() {
            it('add members to group', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.READY;
                var message = {message: "I'm puttin' the band back together!",
                               dest: 'ray@charles.org/ios1234'};
                sandbox.stub(codec, 'encodeMessage', _echo);
                sandbox.stub(participant, '_join').returns(message);
                participant.join(['ray@charles.org/ios1234']);
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._join);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'jake@blues.org/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'ray@charles.org/ios1234');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.AUX_UPFLOW);
            });

            it('illegal state transition', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var illegalStates = [greeter.STATE.NULL,
                                     greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.INIT_DOWNFLOW,
                                     greeter.STATE.AUX_UPFLOW,
                                     greeter.STATE.AUX_DOWNFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.state = illegalStates[i];
                    assert.throws(function() { participant.join(); },
                                  'join() can only be called from a ready state.');
                }
            });
        });

        describe('#exclude() method', function() {
            it('exclude members', function() {
                var participant = new ns.ProtocolHandler('a.dumbledore@hogwarts.ac.uk/android123',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.READY;
                var message = {message: "You're fired!",
                               members: ['a.dumbledore@hogwarts.ac.uk/android123', 'further.staff'],
                               dest: ''};
                sandbox.stub(codec, 'encodeMessage', _echo);
                sandbox.stub(participant, '_exclude').returns(message);
                participant.exclude(['g.lockhart@hogwarts.ac.uk/ios1234']);
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._exclude);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'a.dumbledore@hogwarts.ac.uk/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.AUX_DOWNFLOW);
            });

            it('exclude members in recovery', function() {
                var participant = new ns.ProtocolHandler('mccoy@ncc-1701.mil/android123',
                                                         'NCC-1701',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.AUX_DOWNFLOW;
                participant.recovering = true;
                var message = {message: "He's dead, Jim!",
                               members: ['mccoy@ncc-1701.mil/android123', 'kirk@ncc-1701.mil/android456'],
                               dest: ''};
                sandbox.stub(codec, 'encodeMessage', _echo);
                sandbox.stub(participant, '_exclude').returns(message);
                participant.exclude(['red.shirt@ncc-1701.mil/ios1234']);
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._exclude);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'mccoy@ncc-1701.mil/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.AUX_DOWNFLOW);
                assert.strictEqual(participant.recovering, true);
            });

            it('illegal state transition', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var illegalStates = [greeter.STATE.NULL,
                                     greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.INIT_DOWNFLOW,
                                     greeter.STATE.AUX_UPFLOW,
                                     greeter.STATE.AUX_DOWNFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.state = illegalStates[i];
                    assert.throws(function() { participant.exclude(); },
                                  'exclude() can only be called from a ready state.');
                }
            });

            it('illegal state transition on recovery', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.recovering = true;
                var illegalStates = [greeter.STATE.NULL,
                                     greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.AUX_UPFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.state = illegalStates[i];
                    assert.throws(function() { participant.exclude(); },
                                  'exclude() for recovery can only be called from a ready or downflow state.');
                }
            });

            it('exclude last peer --> quit()', function() {
                var participant = new ns.ProtocolHandler('chingachgook@mohicans.org/android123',
                                                         'Last of the Mohicans',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.READY;
                participant.members = ['chingachgook@mohicans.org/android123',
                                       'uncas@mohicans.org/ios1234'];
                var message = {message: "My poor son!",
                               members: ['chingachgook@mohicans.org/android123'],
                               dest: ''};
                sandbox.stub(participant, '_exclude').returns(message);
                sandbox.stub(participant, 'quit');
                participant.exclude(['uncas@mohicans.org/ios1234']);
                sinon_assert.calledOnce(participant._exclude);
                sinon_assert.calledOnce(participant.quit);
            });
        });

        describe('#quit() method', function() {
            it('no-op test, already in QUIT', function() {
                var participant = new ns.ProtocolHandler('peter@genesis.co.uk/android4711',
                                                         'Genesis',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.QUIT;
                sandbox.spy(participant, '_quit');
                participant.quit();
                assert.strictEqual(participant._quit.callCount, 0);
            });

            it('simple test', function() {
                var participant = new ns.ProtocolHandler('peter@genesis.co.uk/android4711',
                                                         'Genesis',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.READY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                var message = {signingKey: 'Sledge Hammer',
                               source: 'peter@genesis.co.uk/android4711',
                               dest: ''};
                sandbox.stub(codec, 'encodeMessage', _echo);
                participant._quit = stub().returns(message);
                participant.quit();
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._quit);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'peter@genesis.co.uk/android4711');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.QUIT);
            });

            it('impossible call situation', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.NULL;
                assert.throws(function() { participant.quit(); },
                              'Not participating.');
            });

            it('#quit() in workflow', function() {
                this.timeout(this.timeout() * 2);
                // Initialise members.
                var numMembers = 2;
                var participants = {};
                for (var i = 1; i <= numMembers; i++) {
                    participants[i.toString()] = new ns.ProtocolHandler(i.toString(), 'foo',
                                                                        _td.ED25519_PRIV_KEY,
                                                                        _td.ED25519_PUB_KEY,
                                                                        _td.STATIC_PUB_KEY_DIR);
                    participants[i.toString()].sessionKeyStore = _dummySessionStore();
                }

                // Start.
                participants['1'].start(['2']);
                assert.strictEqual(participants['1'].state, greeter.STATE.INIT_UPFLOW);
                var protocolMessage = participants['1'].protocolOutQueue.shift();

                // Processing start/upflow message.
                participants['2'].processMessage(protocolMessage);
                protocolMessage = participants['2'].protocolOutQueue.shift();
                assert.strictEqual(participants['2'].state, greeter.STATE.INIT_DOWNFLOW);
                participants['1'].processMessage(protocolMessage);
                protocolMessage = participants['1'].protocolOutQueue.shift();
                assert.strictEqual(participants['1'].state, greeter.STATE.READY);

                // Participant 2 should process the last confirmation message.
                participants['2'].processMessage(protocolMessage);
                // Participant 2 is also ready.
                assert.strictEqual(participants['2'].state, greeter.STATE.READY);

                participants['1'].quit();
            });
        });

        describe('#refresh() method', function() {
            it('refresh own private key using aka', function() {
                var participant = new ns.ProtocolHandler('dj.jazzy.jeff@rapper.com/android123',
                                                         '80s Rap',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.READY;
                participant.greet.cliquesMember.groupKey = "Parents Just Don't Understand";
                participant.greet.askeMember.ephemeralPubKeys = [];
                var message = {message: "Fresh Prince",
                               dest: ''};
                sandbox.stub(codec, 'encodeMessage', _echo);
                participant._refresh = stub().returns(message);
                participant.refresh();
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._refresh);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'dj.jazzy.jeff@rapper.com/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.READY);
            });

            it('illegal state transition', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var illegalStates = [greeter.STATE.NULL,
                                     greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.AUX_UPFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.state = illegalStates[i];
                    assert.throws(function() { participant.refresh(); },
                                  'refresh() can only be called from a ready or downflow states.');
                }
            });
        });

        describe('#fullRefresh() method', function() {
            it('refresh all using ika', function() {
                var participant = new ns.ProtocolHandler('Earth', 'Solar System',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.AUX_UPFLOW;
                var members = ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                               'Saturn', 'Uranus', 'Neptune', 'Pluto'];
                participant.greet.askeMember.members = utils.clone(members);
                participant.greet.cliquesMember.members = utils.clone(members);
                var message = {message: "Pluto's not a planet any more!!",
                               members: ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                                         'Saturn', 'Uranus', 'Neptune'],
                               dest: 'Mercury'};
                sandbox.stub(codec, 'encodeMessage', _echo);
                sandbox.stub(participant, '_start').returns(message);
                var keepMembers = ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                                   'Saturn', 'Uranus', 'Neptune'];
                participant.fullRefresh(keepMembers);
                sinon_assert.calledOnce(codec.encodeMessage);
                sinon_assert.calledOnce(participant._start);
                sinon.assert.calledWith(participant._start,
                                        ['Mercury', 'Venus', 'Mars', 'Jupiter',
                                         'Saturn', 'Uranus', 'Neptune']);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'Earth');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'Mercury');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.state, greeter.STATE.INIT_UPFLOW);
            });

            it('refresh by excluding last peer --> quit()', function() {
                var participant = new ns.ProtocolHandler('chingachgook@mohicans.org/android123',
                                                         'Last of the Mohicans',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.AUX_UPFLOW;
                var members = ['chingachgook@mohicans.org/android123',
                               'uncas@mohicans.org/ios1234'];
                participant.members = members;
                participant.greet.askeMember.members = utils.clone(members);
                participant.greet.cliquesMember.members = utils.clone(members);
                var message = {message: "The last of us!",
                               members: ['chingachgook@mohicans.org/android123'],
                               dest: ''};
                sandbox.stub(participant, '_start').returns(message);
                sandbox.stub(participant, 'quit');
                participant.fullRefresh(['uncas@mohicans.org/ios1234']);
                sinon_assert.calledOnce(participant._start);
                sinon_assert.calledOnce(participant.quit);
            });
        });

        describe('#recover() method', function() {
            it('simplest recover', function() {
                var participant = new ns.ProtocolHandler('beatrix@kiddo.com/android123',
                                                         'Kill Bill',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.AUX_DOWNFLOW;
                sandbox.stub(participant, 'refresh');
                participant.recover();
                sinon_assert.calledOnce(participant.refresh);
                assert.strictEqual(participant.recovering, true);
            });

            it('full recover', function() {
                var participant = new ns.ProtocolHandler('beatrix@kiddo.com/android123',
                                                         'Kill Bill',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.AUX_UPFLOW;
                sandbox.stub(participant.greet.askeMember, 'discardAuthentications');
                sandbox.stub(participant, 'fullRefresh');
                participant.recover();
                sinon_assert.calledOnce(participant.greet.askeMember.discardAuthentications);
                sinon_assert.calledOnce(participant.fullRefresh);
                assert.strictEqual(participant.recovering, true);
            });

            it('recover members to keep', function() {
                var participant = new ns.ProtocolHandler('beatrix@kiddo.com/android123',
                                                         'Kill Bill',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state =  greeter.STATE.AUX_DOWNFLOW;
                var message = {message: "You're dead!",
                               dest: ''};
                participant.greet.askeMember.members = ['beatrix@kiddo.com/android123',
                                                  'vernita@green.com/outlook4711',
                                                  'o-ren@ishi.jp/ios1234'];
                sandbox.stub(participant.greet.askeMember, 'discardAuthentications');
                sandbox.stub(participant, 'exclude');
                sandbox.stub(codec, 'encodeMessage', _echo);
                participant.recover(['beatrix@kiddo.com/android123', 'o-ren@ishi.jp/ios1234']);
                sinon_assert.calledOnce(participant.greet.askeMember.discardAuthentications);
                sinon_assert.calledOnce(participant.exclude);
                assert.strictEqual(participant.recovering, true);
            });
        });

        describe('#_processErrorMessage() method', function() {
            it('processing for a signed error message', function() {
                var contentParts = _td.ERROR_MESSAGE_PAYLOAD.split(':');
                contentParts.splice(0, 1);
                var content = contentParts.join(':');
                var compare = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                severity: ns.ERROR.TERMINAL,
                                signatureOk: true,
                                message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['a.dumbledore@hogwarts.ac.uk/android123',
                                                  'q.quirrell@hogwarts.ac.uk/wp8possessed666',
                                                  'm.mcgonagall@hogwarts.ac.uk/ios456'];
                participant.greet.askeMember.ephemeralPubKeys = [_td.ED25519_PUB_KEY,
                                                           _td.ED25519_PUB_KEY,
                                                           _td.ED25519_PUB_KEY];
                sandbox.stub(codec, 'verifyMessageSignature').returns(true);
                var result = participant._processErrorMessage(content);
                sinon_assert.calledOnce(codec.verifyMessageSignature);
                assert.strictEqual(codec.verifyMessageSignature.getCall(0).args[1],
                                   'from "a.dumbledore@hogwarts.ac.'
                                   + 'uk/android123":TERMINAL:Signature verifi'
                                   + 'cation for q.quirrell@hogwarts.ac.uk/wp8'
                                   + 'possessed666 failed.');
                assert.deepEqual(result, compare);
            });

            it('processing for a signed error message with no ephem pub keys', function() {
                var contentParts = _td.ERROR_MESSAGE_PAYLOAD.split(':');
                contentParts.splice(0, 1);
                var content = contentParts.join(':');
                var compare = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                severity: ns.ERROR.TERMINAL,
                                signatureOk: null,
                                message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['a.dumbledore@hogwarts.ac.uk/android123',
                                                  'q.quirrell@hogwarts.ac.uk/wp8possessed666',
                                                  'm.mcgonagall@hogwarts.ac.uk/ios456'];
                sandbox.stub(codec, 'verifyMessageSignature');
                var result = participant._processErrorMessage(content);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 0);
                assert.deepEqual(result, compare);
            });

            it('processing for a signed error message sender not in members', function() {
                var contentParts = _td.ERROR_MESSAGE_PAYLOAD.split(':');
                contentParts.splice(0, 1);
                var content = contentParts.join(':');
                var compare = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                severity: ns.ERROR.TERMINAL,
                                signatureOk: null,
                                message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['q.quirrell@hogwarts.ac.uk/wp8possessed666',
                                                  'm.mcgonagall@hogwarts.ac.uk/ios456'];
                participant.greet.askeMember.ephemeralPubKeys = [_td.ED25519_PUB_KEY,
                                                           _td.ED25519_PUB_KEY];
                sandbox.stub(codec, 'verifyMessageSignature');
                var result = participant._processErrorMessage(content);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 0);
                assert.deepEqual(result, compare);
            });

            it('processing for an unsigned error message', function() {
                var contentParts = _td.ERROR_MESSAGE_PAYLOAD.split(':');
                contentParts.splice(0, 1);
                contentParts[0] = '';
                var content = contentParts.join(':');
                var compare = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                severity: ns.ERROR.TERMINAL,
                                signatureOk: null,
                                message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                sandbox.stub(codec, 'verifyMessageSignature');
                var result = participant._processErrorMessage(content);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 0);
                assert.deepEqual(result, compare);
            });
        });

        describe('#send() method', function() {
            it('send a message confidentially', function() {
                var participant = new ns.ProtocolHandler('orzabal@tearsforfears.co.uk/android123',
                                                         'Tears for Fears',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.exponentialPadding = 0;
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = greeter.STATE.READY;
                var message = 'Shout, shout, let it all out!';
                participant.send(message);
                assert.lengthOf(participant.messageOutQueue, 1);
                assert.lengthOf(participant.messageOutQueue[0].message, 188);
                assert.strictEqual(participant.messageOutQueue[0].from, 'orzabal@tearsforfears.co.uk/android123');
                assert.strictEqual(participant.messageOutQueue[0].to, '');
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('send a message confidentially with exponential padding', function() {
                var participant = new ns.ProtocolHandler('orzabal@tearsforfears.co.uk/android123',
                                                         'Tears for Fears',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = greeter.STATE.READY;
                var message = 'Shout, shout, let it all out!';
                participant.send(message);
                assert.lengthOf(participant.messageOutQueue, 1);
                assert.lengthOf(participant.messageOutQueue[0].message, 320);
                assert.strictEqual(participant.messageOutQueue[0].from, 'orzabal@tearsforfears.co.uk/android123');
                assert.strictEqual(participant.messageOutQueue[0].to, '');
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('on uninitialised state', function() {
                var participant = new ns.ProtocolHandler('kenny@southpark.com/android123',
                                                         'South Park',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.INIT_DOWNFLOW;
                assert.throws(function() { participant.send('Wassup?'); },
                              'Messages can only be sent in ready state.');
            });
        });

        describe('#sendTo() method', function() {
            it('send a directed message confidentially', function() {
                var participant = new ns.ProtocolHandler('jennifer@rush.com/android123',
                                                         '80s Pop',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.exponentialPadding = 0;
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = greeter.STATE.READY;
                var message = 'Whispers in the morning ...';
                participant.sendTo(message, 'my_man@rush.com/ios12345');
                assert.lengthOf(participant.messageOutQueue, 1);
                assert.lengthOf(participant.messageOutQueue[0].message, 188);
                assert.strictEqual(participant.messageOutQueue[0].from, 'jennifer@rush.com/android123');
                assert.strictEqual(participant.messageOutQueue[0].to, 'my_man@rush.com/ios12345');
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('send a directed message confidentially with exponential padding', function() {
                var participant = new ns.ProtocolHandler('jennifer@rush.com/android123',
                                                         '80s Pop',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = greeter.STATE.READY;
                var message = 'Whispers in the morning ...';
                participant.sendTo(message, 'my_man@rush.com/ios12345');
                assert.lengthOf(participant.messageOutQueue, 1);
                assert.lengthOf(participant.messageOutQueue[0].message, 320);
                assert.strictEqual(participant.messageOutQueue[0].from, 'jennifer@rush.com/android123');
                assert.strictEqual(participant.messageOutQueue[0].to, 'my_man@rush.com/ios12345');
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });
        });

        describe('#sendError() method', function() {
            it('send an mpENC protocol error message', function() {
                var participant = new ns.ProtocolHandler('a.dumbledore@hogwarts.ac.uk/android123',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                participant.state = greeter.STATE.AUX_DOWNFLOW;
                sandbox.stub(participant, 'quit');
                var message = 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
                participant.sendError(ns.ERROR.TERMINAL, message);
                var outMessage = participant.protocolOutQueue[0].message;
                assert.strictEqual(participant.protocolOutQueue[0].message, _td.ERROR_MESSAGE_PAYLOAD);
                assert.strictEqual(participant.protocolOutQueue[0].from, participant.id);
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.uiQueue, 0);
                sinon_assert.calledOnce(participant.quit);
            });

            it('illegal error severity', function() {
                var participant = new ns.ProtocolHandler('asok@dilbertsintern.org/android123',
                                                         'Dilbert',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = 'Problem retrieving public key for: PointyHairedBoss';
                assert.throws(function() { participant.sendError(42, message); },
                              'Illegal error severity: 42.');
            });
        });

        describe('#inspectMessage() method', function() {
            it('on plain text message', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: 'Pōkarekare ana ngā wai o Waitemata, whiti atu koe hine marino ana e.',
                               from: 'kiri@singer.org.nz/waiata42'};
                var result = participant.inspectMessage(message);
                assert.deepEqual(result, {type: 'plain'});
            });

            it('on error message', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: '?mpENC Error:Hatschi!',
                               from: 'common@cold.govt.nz/flu2'};
                var result = participant.inspectMessage(message);
                assert.deepEqual(result, {type: 'mpENC error'});
            });

            it('on binary data message', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.READY;
                var message = {message: _td.DATA_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var result = participant.inspectMessage(message);
                assert.deepEqual(result, {type: 'mpENC data message'});
            });

            it('on query message', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?foo.',
                               from: 'raw@hide.com/rollingrollingrolling'};
                var result = participant.inspectMessage(message);
                assert.deepEqual(result, {type: 'mpENC query'});
            });

            it("initial start message for other", function() {
                var participant = new ns.ProtocolHandler('3', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '2', origin: null,
                              agreement: 'initial', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5'],
                              numNonces: 1, numIntKeys: 2, numPubKeys: 1});
                var message = {message: _td.UPFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '2', origin: '???',
                                agreement: 'initial', flow: 'up',
                                fromInitiator: true, negotiation: 'start other',
                                members: ['1', '2', '3', '4', '5'],
                                numNonces: 1, numIntKeys: 2, numPubKeys: 1};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("initial start message for me", function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '2', origin: null,
                              agreement: 'initial', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5'],
                              numNonces: 1, numIntKeys: 2, numPubKeys: 1});
                var message = {message: _td.UPFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '2', origin: '???',
                                agreement: 'initial', flow: 'up',
                                fromInitiator: true, negotiation: 'start me',
                                members: ['1', '2', '3', '4', '5'],
                                numNonces: 1, numIntKeys: 2, numPubKeys: 1};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it('on own quit binary message', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4', '5'];
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: '1'};
                var expected = {protocolVersion: 1,
                                messageType: 0xd3,
                                messageTypeString: 'QUIT_DOWN',
                                from: '1', to: '',
                                origin: 'initiator (self)',
                                operation: 'QUIT',
                                agreement: 'auxiliary',
                                flow: 'down',
                                recover: false,
                                members: [],
                                numNonces: 0, numIntKeys: 0, numPubKeys: 0};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("on someone's quit binary message", function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4', '5'];
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: '1'};
                var expected = {protocol: 1,
                                from: '1', to: '',
                                origin: 'initiator',
                                agreement: 'auxiliary',
                                flow: 'down',
                                members: [],
                                numNonces: 0, numIntKeys: 0, numPubKeys: 0};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it('exclude me message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4', '5'];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '', origin: null,
                              agreement: 'auxiliary', flow: 'down',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '3', '4', '5'],
                              numNonces: 0, numIntKeys: 4, numPubKeys: 0});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '', origin: 'participant',
                                agreement: 'auxiliary', flow: 'down',
                                fromInitiator: true, negotiation: 'exclude me',
                                members: ['1', '3', '4', '5'],
                                numNonces: 0, numIntKeys: 4, numPubKeys: 0};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("exclude other message", function() {
                var participant = new ns.ProtocolHandler('3', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4', '5'];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '', origin: null,
                              agreement: 'auxiliary', flow: 'down',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '3', '4', '5'],
                              numNonces: 0, numIntKeys: 4, numPubKeys: 0});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '', origin: 'participant',
                                agreement: 'auxiliary', flow: 'down',
                                fromInitiator: true, negotiation: 'exclude other',
                                members: ['1', '3', '4', '5'],
                                numNonces: 0, numIntKeys: 4, numPubKeys: 0};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it('join me message', function() {
                var participant = new ns.ProtocolHandler('5', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = [];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '5', origin: null,
                              agreement: 'auxiliary', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5'],
                              numNonces: 4, numIntKeys: 5, numPubKeys: 4});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '5', origin: '???',
                                agreement: 'auxiliary', flow: 'up',
                                fromInitiator: null, negotiation: 'join me',
                                members: ['1', '2', '3', '4', '5'],
                                numNonces: 4, numIntKeys: 5, numPubKeys: 4};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("join other message", function() {
                var participant = new ns.ProtocolHandler('4', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4'];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '5', origin: null,
                              agreement: 'auxiliary', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5'],
                              numNonces: 4, numIntKeys: 5, numPubKeys: 4});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '5', origin: 'participant',
                                agreement: 'auxiliary', flow: 'up',
                                fromInitiator: true, negotiation: 'join other',
                                members: ['1', '2', '3', '4', '5'],
                                numNonces: 4, numIntKeys: 5, numPubKeys: 4};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("join other message chained", function() {
                var participant = new ns.ProtocolHandler('4', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4'];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '5', to: '6', origin: null,
                              agreement: 'auxiliary', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5', '6'],
                              numNonces: 5, numIntKeys: 6, numPubKeys: 5});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '5', to: '6', origin: 'outsider',
                                agreement: 'auxiliary', flow: 'up',
                                fromInitiator: false, negotiation: 'join other',
                                members: ['1', '2', '3', '4', '5', '6'],
                                numNonces: 5, numIntKeys: 6, numPubKeys: 5};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("join message (not involved)", function() {
                var participant = new ns.ProtocolHandler('4', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '5', origin: null,
                              agreement: 'auxiliary', flow: 'up',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '5'],
                              numNonces: 3, numIntKeys: 4, numPubKeys: 3});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '5', origin: '???',
                                agreement: 'auxiliary', flow: 'up',
                                fromInitiator: null, negotiation: 'join (not involved)',
                                members: ['1', '2', '3', '5'],
                                numNonces: 3, numIntKeys: 4, numPubKeys: 3};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });

            it("refresh message", function() {
                var participant = new ns.ProtocolHandler('4', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.askeMember.members = ['1', '2', '3', '4', '5'];
                sandbox.stub(codec, 'inspectMessageContent').returns(
                             {type: null, protocol: 1,
                              from: '1', to: '', origin: null,
                              agreement: 'auxiliary', flow: 'down',
                              fromInitiator: null, negotiation: null,
                              members: ['1', '2', '3', '4', '5'],
                              numNonces: 0, numIntKeys: 5, numPubKeys: 0});
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                var expected = {protocol: 1,
                                from: '1', to: '', origin: 'participant',
                                agreement: 'auxiliary', flow: 'down',
                                fromInitiator: true, negotiation: 'refresh',
                                members: ['1', '2', '3', '4', '5'],
                                numNonces: 0, numIntKeys: 5, numPubKeys: 0};
                var result = participant.inspectMessage(message);
                assert.ok(_tu.deepCompare(result, expected));
            });
        });

        describe('#processMessage() method', function() {
            it('on plain text message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: 'Pōkarekare ana ngā wai o Waitemata, whiti atu koe hine marino ana e.',
                               from: 'kiri@singer.org.nz/waiata42'};
                participant.processMessage(message);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0].message.substring(0, 9),
                                   '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?');
                assert.strictEqual(participant.protocolOutQueue[0].from,
                                   '2');
                assert.strictEqual(participant.protocolOutQueue[0].to,
                                   'kiri@singer.org.nz/waiata42');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'info');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'Received unencrypted message, requesting encryption.');
            });

            // TODO:
            // * check for message showing in ui queue
            // * INFO, WARNING, TERMINAL ERROR, type "error"
            // * invoke quit() on TERMINAL ERROR

            it('on TERMINAL error message', function() {
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var messageProperties = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                          severity: ns.ERROR.TERMINAL,
                                          signatureOk: true,
                                          message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var message = {message: 'dummy',
                               from: 'a.dumbledore@hogwarts.ac.uk/android123'};
                sandbox.stub(codec, 'categoriseMessage').returns({ category: codec.MESSAGE_CATEGORY.MPENC_ERROR,
                                                                   content: 'foo' });
                sandbox.stub(participant, '_processErrorMessage').returns(messageProperties);
                sandbox.stub(participant, 'quit');
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(participant._processErrorMessage);
                sinon_assert.calledOnce(participant.quit);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'error');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'TERMINAL ERROR: Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.');
            });

            it('on WARNING error message', function() {
                var participant = new ns.ProtocolHandler('m.mcgonagall@hogwarts.ac.uk/ios456',
                                                         'Hogwarts',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var messageProperties = { from: 'a.dumbledore@hogwarts.ac.uk/android123',
                                          severity: ns.ERROR.WARNING,
                                          signatureOk: true,
                                          message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
                var message = {message: 'dummy',
                               from: 'a.dumbledore@hogwarts.ac.uk/android123'};
                sandbox.stub(codec, 'categoriseMessage').returns({ category: codec.MESSAGE_CATEGORY.MPENC_ERROR,
                                                                   content: 'foo' });
                sandbox.stub(participant, '_processErrorMessage').returns(messageProperties);
                sandbox.stub(participant, 'quit');
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(participant._processErrorMessage);
                assert.strictEqual(participant.quit.callCount, 0);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'error');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'WARNING: Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.');
            });

            it('on keying message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var groupKey = _td.GROUP_KEY.substring(0, 16);
                participant.greet.cliquesMember.groupKey = groupKey;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                sandbox.stub(codec, 'categoriseMessage').returns(
                        { category: codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                          content: 'foo' });
                sandbox.stub(codec, 'decodeMessageContent').returns(_td.DOWNFLOW_MESSAGE_STRING);
                sandbox.stub(participant.greet, '_processMessage').returns(
                        { decodedMessage: _td.DOWNFLOW_MESSAGE_STRING,
                          newState: greeter.STATE.READY });
                sandbox.stub(codec, 'encodeMessage', _echo);
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(codec.decodeMessageContent);
                sinon_assert.calledOnce(participant.greet._processMessage);
                sinon_assert.calledOnce(codec.encodeMessage);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0].message, _td.DOWNFLOW_MESSAGE_STRING);
                assert.strictEqual(participant.protocolOutQueue[0].from, '2');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('on own keying message with flushed ephemeralPubKeys', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY.substring(0, 16);
                participant.greet.askeMember.ephemeralPubKeys = [];
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                var message = {message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                               from: '1'};
                sandbox.stub(codec, 'categoriseMessage').returns(
                        { category: codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                          content: 'foo' });
                sandbox.stub(codec, 'decodeMessageContent').returns(_td.DOWNFLOW_MESSAGE_STRING);
                sandbox.stub(participant.greet, '_processMessage').returns(
                        { decodedMessage: _td.DOWNFLOW_MESSAGE_STRING,
                          newState: greeter.STATE.READY });
                sandbox.stub(codec, 'encodeMessage', _echo);
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(codec.decodeMessageContent);
                assert.strictEqual(codec.decodeMessageContent.getCall(0).args[1], _td.ED25519_PUB_KEY);
                sinon_assert.calledOnce(participant.greet._processMessage);
                sinon_assert.calledOnce(codec.encodeMessage);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0].message, _td.DOWNFLOW_MESSAGE_STRING);
                assert.strictEqual(participant.protocolOutQueue[0].from, '1');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('on data message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.state = greeter.STATE.READY;
                var groupKey = _td.GROUP_KEY.substring(0, 16);
                participant.greet.cliquesMember.groupKey = groupKey;
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                var message = {message: _td.DATA_MESSAGE_PAYLOAD,
                               from: 'bar@baz.nl/blah123'};
                sandbox.stub(participant.tryDecrypt, 'trial');
                participant.processMessage(message);
                assert.strictEqual(participant.tryDecrypt.trial.callCount, 1);
                assert.lengthOf(participant.tryDecrypt.trial.getCall(0).args, 1);
                assert.deepEqual(participant.tryDecrypt.trial.getCall(0).args[0], message);
            });

            it('on query message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?foo.',
                               from: 'raw@hide.com/rollingrollingrolling'};
                participant.start = stub();
                participant.processMessage(message);
                sinon_assert.calledOnce(participant.start);
            });

            it('on quit message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var message = {message: '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?foo.',
                               from: 'raw@hide.com/rollingrollingrolling'};
                participant.start = stub();
                participant.processMessage(message);
                sinon_assert.calledOnce(participant.start);
            });
        });

        describe("complex flow cases", function() {
            it('for 3 members, 2 joining, 2 others leaving, send message, refresh key, full recovery', function() {
                // Extend timeout, this test takes longer.
                this.timeout(this.timeout() * 30);
                var numMembers = 3;
                var initiator = 0;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    var newMember = new ns.ProtocolHandler(i.toString(), 'wave tank',
                                                           _td.ED25519_PRIV_KEY,
                                                           _td.ED25519_PUB_KEY,
                                                           _td.STATIC_PUB_KEY_DIR);
                    participants.push(newMember);
                }
                var otherMembers = [];
                for (var i = 2; i <= numMembers; i++) {
                    otherMembers.push(i.toString());
                }

                var startTime = Math.round(Date.now() / 1000);
                console.log('Starting at ' + Math.round(Date.now() / 1000 - startTime));
                // Start.
                participants[initiator].start(otherMembers);
                var message = participants[initiator].protocolOutQueue.shift();
                var payload = _getPayload(message, _getSender(message, participants, members));
                assert.strictEqual(participants[initiator].state, greeter.STATE.INIT_UPFLOW);

                console.log('Upflow for start at ' + Math.round(Date.now() / 1000 - startTime));
                // Upflow.
                while (message && payload.dest !== '') {
                    var nextId = payload.members.indexOf(payload.dest);
                    participants[nextId].processMessage(message);
                    message = participants[nextId].protocolOutQueue.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                                        if (payload.dest === '') {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.INIT_DOWNFLOW);
                    } else {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.INIT_UPFLOW);
                    }
                }

                console.log('Downflow for start at ' + Math.round(Date.now() / 1000 - startTime));
                // Downflow.
                var nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage =  participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.INIT_DOWNFLOW);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                var keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                }

                console.log('Joining two new at ' + Math.round(Date.now() / 1000 - startTime));
                // Join two new guys.
                var newMembers = ['4', '5'];
                members = members.concat(newMembers);
                for (var i = 0; i < newMembers.length; i++) {
                    var newMember = new ns.ProtocolHandler(newMembers[i], 'wave tank',
                                                           _td.ED25519_PRIV_KEY,
                                                           _td.ED25519_PUB_KEY,
                                                           _td.STATIC_PUB_KEY_DIR);
                    participants.push(newMember);
                }

                // '2' starts upflow for join.
                participants[1].join(newMembers);
                message = participants[1].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));

                console.log('Upflow for join at ' + Math.round(Date.now() / 1000 - startTime));
                // Upflow for join.
                while (payload.dest !== '') {
                    var nextId = payload.members.indexOf(payload.dest);
                    participants[nextId].processMessage(message);
                    message = participants[nextId].protocolOutQueue.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                    if (payload.dest === '') {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.AUX_DOWNFLOW);
                    } else {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.AUX_UPFLOW);
                    }
                }

                console.log('Downflow for join at ' + Math.round(Date.now() / 1000 - startTime));
                // Downflow for join.
                nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.AUX_DOWNFLOW);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                }

                console.log('Excluding two at ' + Math.round(Date.now() / 1000 - startTime));
                // '4' excludes two members.
                var toExclude = ['1', '3'];
                for (var i = 0; i < toExclude.length; i++) {
                    var delIndex = members.indexOf(toExclude[i]);
                    members.splice(delIndex, 1);
                    participants.splice(delIndex, 1);
                }
                participants[1].exclude(toExclude);
                message = participants[1].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                members = payload.members;

                console.log('Downflow for exclude at ' + Math.round(Date.now() / 1000 - startTime));
                // Downflow for exclude.
                nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.AUX_DOWNFLOW);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                }

                console.log('Messaging at ' + Math.round(Date.now() / 1000 - startTime));
                // '5' sends a confidential text message to the group.
                participants[2].send('Rock me Amadeus');
                message = participants[2].messageOutQueue.shift();

                // Received message for all.
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    var messageClone = utils.clone(message);
                    participant.processMessage(messageClone);
                    var uiMessage = participant.uiQueue.shift();
                    assert.strictEqual(uiMessage.message, 'Rock me Amadeus');
                    assert.strictEqual(uiMessage.type, 'message');
                    assert.strictEqual(uiMessage.from, '5');
                }

                console.log('Refreshing at ' + Math.round(Date.now() / 1000 - startTime));
                // '2' initiates a key refresh.
                var oldGroupKey = participants[0].greet.cliquesMember.groupKey;
                var oldPrivKeyListLength = participants[0].greet.cliquesMember.privKeyList.length;
                participants[0].refresh();
                message = participants[0].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                assert.lengthOf(participants[0].greet.cliquesMember.privKeyList, oldPrivKeyListLength + 1);
                assert.notStrictEqual(participants[0].greet.cliquesMember.groupKey, oldGroupKey);

                console.log('Downflow for refresh at ' + Math.round(Date.now() / 1000 - startTime));
                // Downflow for refresh.
                nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        oldPrivKeyListLength = participant.greet.cliquesMember.privKeyList.length;
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.AUX_DOWNFLOW);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.notStrictEqual(participant.greet.cliquesMember.groupKey, oldGroupKey);
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                }

                console.log('Recovering at ' + Math.round(Date.now() / 1000 - startTime));
                // '5' starts a full recovery.
                participants[2].state = greeter.STATE.AUX_UPFLOW; // The glitch, where things got stuck.
                oldGroupKey = participants[2].greet.cliquesMember.groupKey;
                var oldSigningKey = participants[2].greet.askeMember.ephemeralPrivKey;
                // Should do a fullRefresh()
                participants[2].recover();
                assert.strictEqual(participants[2].recovering, true);
                message = participants[2].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                assert.lengthOf(participants[2].greet.cliquesMember.privKeyList, 1);
                assert.strictEqual(participants[2].greet.askeMember.ephemeralPrivKey, oldSigningKey);
                // Sort participants.
                var tempParticipants = [];
                for (var i = 0; i < payload.members.length; i++) {
                    var index = members.indexOf(payload.members[i]);
                    tempParticipants.push(participants[index]);
                }
                participants = tempParticipants;
                members = payload.members;

                console.log('Upflow for recover at ' + Math.round(Date.now() / 1000 - startTime));
                // Upflow for recovery.
                while (payload.dest !== '') {
                    var nextId = payload.members.indexOf(payload.dest);
                    oldSigningKey = participants[nextId].greet.askeMember.ephemeralPrivKey;
                    participants[nextId].processMessage(message);
                    assert.strictEqual(participants[nextId].recovering, true);
                    assert.strictEqual(participants[nextId].greet.askeMember.ephemeralPrivKey, oldSigningKey);
                    message = participants[nextId].protocolOutQueue.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                    if (payload.dest === '') {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.INIT_DOWNFLOW);
                    } else {
                        assert.strictEqual(participants[nextId].state, greeter.STATE.INIT_UPFLOW);
                    }
                }

                console.log('Downflow for recover at ' + Math.round(Date.now() / 1000 - startTime));
                // Downflow for recovery.
                nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                            assert.strictEqual(participant.recovering, false);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.INIT_DOWNFLOW);
                            assert.strictEqual(participant.recovering, true);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                    assert.notStrictEqual(participant.greet.cliquesMember.groupKey, oldGroupKey);
                }
            });

            it('for two initiated by plain text message, quit', function() {
                // Extend timeout, this test takes longer.
                this.timeout(this.timeout() * 10);
                var numMembers = 2;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    var newMember = new ns.ProtocolHandler(i.toString(), 'wave tank',
                                                           _td.ED25519_PRIV_KEY,
                                                           _td.ED25519_PUB_KEY,
                                                           _td.STATIC_PUB_KEY_DIR);
                    participants.push(newMember);
                }
                var message = {message: 'Kia ora', from: '1', to: '2'};
                var payload = null;

                // Processing plain text message.
                participants[1].processMessage(message);
                message = participants[1].protocolOutQueue.shift();
                assert.strictEqual(message.message.substring(0, 9),
                                   '?mpENCv' + version.PROTOCOL_VERSION.charCodeAt(0) + '?');
                assert.strictEqual(message.from, '2');
                assert.strictEqual(message.to, '1');
                var uiMessage = participants[1].uiQueue.shift();
                assert.strictEqual(uiMessage.type, 'info');
                assert.strictEqual(uiMessage.message, 'Received unencrypted message, requesting encryption.');
                assert.strictEqual(participants[1].state, greeter.STATE.NULL);

                // Process mpENC query response.
                participants[0].processMessage(message);
                message = participants[0].protocolOutQueue.shift();
                payload = _getPayload(message, participants[0]);
                assert.strictEqual(payload.source, '1');
                assert.strictEqual(payload.dest, '2');
                assert.strictEqual(payload.messageType, codec.MESSAGE_TYPE.INIT_INITIATOR_UP);
                assert.strictEqual(participants[0].state, greeter.STATE.INIT_UPFLOW);

                // Process key agreement upflow.
                participants[1].processMessage(message);
                message = participants[1].protocolOutQueue.shift();
                payload = _getPayload(message, participants[1]);
                assert.strictEqual(payload.source, '2');
                assert.strictEqual(payload.dest, '');
                assert.strictEqual(payload.messageType, codec.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN);
                assert.strictEqual(participants[1].state, greeter.STATE.INIT_DOWNFLOW);

                // Downflow for both.
                var nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.greet.askeMember.isSessionAcknowledged()) {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.INIT_DOWNFLOW);
                        }
                        assert.deepEqual(participant.greet.cliquesMember.members, members);
                        assert.deepEqual(participant.greet.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }
                var keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (members.indexOf(participant.id) < 0) {
                        continue;
                    }
                    if (!keyCheck) {
                        keyCheck = participant.greet.cliquesMember.groupKey;
                    } else {
                        assert.strictEqual(participant.greet.cliquesMember.groupKey, keyCheck);
                    }
                    assert.ok(participant.greet.askeMember.isSessionAcknowledged());
                    assert.strictEqual(participant.state, greeter.STATE.READY);
                    assert.lengthOf(participant.protocolOutQueue, 0);
                    assert.lengthOf(participant.uiQueue, 0);
                    assert.lengthOf(participant.messageOutQueue, 0);
                }

                // '2' quits participation.
                participants[1].quit();
                message = participants[1].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));

                // Downflow for quit.
                nextMessages = [];
                while (payload) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        participant.processMessage(message);
                        var nextMessage = participant.protocolOutQueue.shift();
                        if (nextMessage) {
                            nextMessages.push(utils.clone(nextMessage));
                        }
                        if (participant.id === '2') {
                            assert.strictEqual(participant.state, greeter.STATE.QUIT);
                            assert.deepEqual(participant.greet.cliquesMember.members, ['1']);
                            assert.deepEqual(participant.greet.askeMember.members, ['1']);
                        } else {
                            assert.strictEqual(participant.state, greeter.STATE.READY);
                            assert.deepEqual(participant.greet.cliquesMember.members, members);
                            assert.deepEqual(participant.greet.askeMember.members, members);
                        }
                    }
                    message = nextMessages.shift();
                    payload = _getPayload(message, _getSender(message, participants, members));
                }

                // '1' Now invokes the exclude() for a member who has invoked QUIT.
                // This results (by the last-man-standing principle) in a QUIT message by '1' as well.
                participants[0].exclude(['2']);
                message = participants[0].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                assert.strictEqual(participants[0].state, greeter.STATE.QUIT);
                assert.strictEqual(message.messageType, codec.MESSAGE_TYPE.QUIT);
            });
        });

        it('with delayed message arrival on initialisation', function() {
            this.timeout(this.timeout() * 2);
            // Initialise members.
            var numMembers = 2;
            var participants = {};
            for (var i = 1; i <= numMembers; i++) {
                participants[i.toString()] = new ns.ProtocolHandler(i.toString(), 'wave tank',
                                                                    _td.ED25519_PRIV_KEY,
                                                                    _td.ED25519_PUB_KEY,
                                                                    _td.STATIC_PUB_KEY_DIR);
            }

            // Start.
            participants['1'].start(['2']);
            var protocolMessage = participants['1'].protocolOutQueue.shift();
            assert.strictEqual(participants['1'].state, greeter.STATE.INIT_UPFLOW);

            // Processing start/upflow message.
            participants['2'].processMessage(protocolMessage);
            protocolMessage = participants['2'].protocolOutQueue.shift();
            assert.strictEqual(participants['2'].state, greeter.STATE.INIT_DOWNFLOW);

            // Process first downflow message.
            participants['1'].processMessage(protocolMessage);
            protocolMessage = participants['1'].protocolOutQueue.shift();
            assert.strictEqual(participants['1'].state, greeter.STATE.READY);

            // Final downflow for '2' is still missing ...
            // ... but '1' is already sending.
            participants['1'].send("Harry, fahr' schon mal den Wagen vor!");
            var dataMessage = participants['1'].messageOutQueue.shift();

            // Now '2' is receiving before being ready.
            assert.throws(function() { participants['2'].processMessage(dataMessage); },
                          'Data messages can only be decrypted from a ready state.');
        });

        it('out of order flow by callbacks triggered before state is READY (bug 283)', function() {
            this.timeout(this.timeout() * 2);
            // Initialise members.
            var numMembers = 2;
            var participants = {};
            for (var i = 1; i <= numMembers; i++) {
                participants[i.toString()] = new ns.ProtocolHandler(i.toString(), 'wave tank',
                                                                    _td.ED25519_PRIV_KEY,
                                                                    _td.ED25519_PUB_KEY,
                                                                    _td.STATIC_PUB_KEY_DIR);
            }

            // Start.
            participants['1'].start(['2']);
            var protocolMessage = participants['1'].protocolOutQueue.shift();
            assert.strictEqual(participants['1'].state, greeter.STATE.INIT_UPFLOW);

            // Processing start/upflow message.
            participants['2'].processMessage(protocolMessage);
            protocolMessage = participants['2'].protocolOutQueue.shift();
            assert.strictEqual(participants['2'].state, greeter.STATE.INIT_DOWNFLOW);

            // This 'stateUpdatedCallback' will add a assert() to ensure that
            // the .state is set to READY, after the protocolOutQueue got
            // a new message added (not before!)
            participants['1'].stateUpdatedCallback = function(h) {
                if(this.state === greeter.STATE.READY) {
                    assert.strictEqual(participants['1'].protocolOutQueue.length, 1);
                }
            };

            // Now process the first downflow message.
            // This will also trigger the .statusUpdateCallback, which will
            // guarantee that .protocolOutQueue contains exactly 1 message in
            // the queue.
            participants['1'].processMessage(protocolMessage);
            protocolMessage = participants['1'].protocolOutQueue.shift();
            assert.strictEqual(participants['1'].state, greeter.STATE.READY);
            // We don't need this check anymore, let's remove it.
            participants['1'].stateUpdatedCallback = function(h) {};

            // Participant 2 should process the new protocolOut message.
            participants['2'].processMessage(protocolMessage);
            // Participant 2 is also ready.
            assert.strictEqual(participants['2'].state, greeter.STATE.READY);

            // This was the problematic part:
            // 1 (room owner, who started the flow) sees he is in READY
            // state, so he tries to send a message to 2, meanwhile 2 is still
            // not ready, yet.

            // Note: the correct state/protocolOutQueue is now verified with
            //       the .statusUpdateCallback callback (see above).

            // Test message sending: jid1 -> jid2
            participants['1'].send("How you doin'?", {});

            participants['2'].processMessage(
                participants['1'].messageOutQueue.shift()
            );

            assert.strictEqual(participants['2'].uiQueue[0].message, "How you doin'?");
            assert.strictEqual(participants['2'].uiQueue[0].from, "1");
            assert.strictEqual(participants['2'].uiQueue[0].type, "message");
        }); // END: complex flow cases
    });
});
