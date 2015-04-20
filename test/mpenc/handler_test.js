/**
 * @fileOverview
 * Test of the `mpenc/handler` module.
 */

/*
 * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

    MegaLogger._logRegistry.assert.options.isEnabled = false;

    // set test data
    _td.DATA_MESSAGE_CONTENT.protocol = version.PROTOCOL_VERSION;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        sandbox.stub(MegaLogger._logRegistry.handler, '_log');
    });

    afterEach(function() {
        sandbox.restore();
    });

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
                sandbox.spy(codec, 'decodeDataMessage');
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
                assert.strictEqual(codec.decodeDataMessage.callCount, 1);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 1);
            });

            it('succeeding try func, not pending, previous session', function() {
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                sandbox.spy(codec, 'inspectMessageContent');
                sandbox.spy(codec, 'decodeDataMessage');
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
                assert.strictEqual(codec.decodeDataMessage.callCount, 1);
                assert.strictEqual(codec.verifyMessageSignature.callCount, 1);
            });

            it('succeeding try func, not pending, hint collision', function() {
                var collidingKey = 'XqtAZ4L9eY4qFdf6XsfgsQ==';
                sandbox.stub(codec, 'categoriseMessage').returns(
                    { category: codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                      content: _td.DATA_MESSAGE_STRING }
                );
                sandbox.spy(codec, 'inspectMessageContent');
                sandbox.spy(codec, 'decodeDataMessage');
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
                assert.strictEqual(codec.decodeDataMessage.callCount, 1);
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
                assert.ok(handler.greet.staticPubKeyDir);
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
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                sandbox.stub(participant.greet, 'start').returns(message);
                participant.start(['elwood@blues.org/ios1234']);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.start);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'jake@blues.org/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'elwood@blues.org/ios1234');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.INIT_UPFLOW);
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
                    participant.greet.state = illegalStates[i];
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
                participant.greet.state = greeter.STATE.READY;
                var message = {message: "I'm puttin' the band back together!",
                               dest: 'ray@charles.org/ios1234'};
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                sandbox.stub(participant.greet, 'join').returns(message);
                participant.join(['ray@charles.org/ios1234']);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.join);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'jake@blues.org/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'ray@charles.org/ios1234');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.AUX_UPFLOW);
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
                    participant.greet.state = illegalStates[i];
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
                participant.greet.state = greeter.STATE.READY;
                var message = {message: "You're fired!",
                               members: ['a.dumbledore@hogwarts.ac.uk/android123', 'further.staff'],
                               dest: ''};
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                sandbox.stub(participant.greet, 'exclude').returns(message);
                participant.exclude(['g.lockhart@hogwarts.ac.uk/ios1234']);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.exclude);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'a.dumbledore@hogwarts.ac.uk/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.AUX_DOWNFLOW);
            });

            it('exclude members in recovery', function() {
                var participant = new ns.ProtocolHandler('mccoy@ncc-1701.mil/android123',
                                                         'NCC-1701',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state = greeter.STATE.AUX_DOWNFLOW;
                participant.greet.recovering = true;
                var message = {message: "He's dead, Jim!",
                               members: ['mccoy@ncc-1701.mil/android123', 'kirk@ncc-1701.mil/android456'],
                               dest: ''};
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                sandbox.stub(participant.greet, 'exclude').returns(message);
                participant.exclude(['red.shirt@ncc-1701.mil/ios1234']);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.exclude);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'mccoy@ncc-1701.mil/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.AUX_DOWNFLOW);
                assert.strictEqual(participant.greet.recovering, true);
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
                    participant.greet.state = illegalStates[i];
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
                participant.greet.recovering = true;
                var illegalStates = [greeter.STATE.NULL,
                                     greeter.STATE.INIT_UPFLOW,
                                     greeter.STATE.AUX_UPFLOW];
                for (var i = 0; i < illegalStates.length; i++) {
                    participant.greet.state = illegalStates[i];
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
                participant.greet.state = greeter.STATE.READY;
                participant.members = ['chingachgook@mohicans.org/android123',
                                       'uncas@mohicans.org/ios1234'];
                var message = {message: "My poor son!",
                               members: ['chingachgook@mohicans.org/android123'],
                               dest: ''};
                sandbox.stub(participant.greet, 'exclude').returns(message);
                sandbox.stub(participant, 'quit');
                participant.exclude(['uncas@mohicans.org/ios1234']);
                sinon_assert.calledOnce(participant.greet.exclude);
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
                participant.greet.state =  greeter.STATE.QUIT;
                sandbox.spy(participant.greet, 'quit');
                participant.quit();
                assert.strictEqual(participant.greet.quit.callCount, 0);
            });

            it('simple test', function() {
                var participant = new ns.ProtocolHandler('peter@genesis.co.uk/android4711',
                                                         'Genesis',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state =  greeter.STATE.READY;
                participant.greet.askeMember.ephemeralPrivKey = _td.ED25519_PRIV_KEY;
                var message = {signingKey: 'Sledge Hammer',
                               source: 'peter@genesis.co.uk/android4711',
                               dest: ''};
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.greet.quit = stub().returns(message);
                participant.quit();
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.quit);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'peter@genesis.co.uk/android4711');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.QUIT);
            });

            it('impossible call situation', function() {
                var participant = new ns.ProtocolHandler('jake@blues.org/android123',
                                                         'Blues Brothers',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state = greeter.STATE.NULL;
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
                assert.strictEqual(participants['1'].greet.state, greeter.STATE.INIT_UPFLOW);
                var protocolMessage = participants['1'].protocolOutQueue.shift();

                // Processing start/upflow message.
                participants['2'].processMessage(protocolMessage);
                protocolMessage = participants['2'].protocolOutQueue.shift();
                assert.strictEqual(participants['2'].greet.state, greeter.STATE.INIT_DOWNFLOW);
                participants['1'].processMessage(protocolMessage);
                protocolMessage = participants['1'].protocolOutQueue.shift();
                assert.strictEqual(participants['1'].greet.state, greeter.STATE.READY);

                // Participant 2 should process the last confirmation message.
                participants['2'].processMessage(protocolMessage);
                // Participant 2 is also ready.
                assert.strictEqual(participants['2'].greet.state, greeter.STATE.READY);

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
                participant.greet.state =  greeter.STATE.READY;
                participant.greet.cliquesMember.groupKey = "Parents Just Don't Understand";
                participant.greet.askeMember.ephemeralPubKeys = [];
                var message = { message: "Fresh Prince",
                                dest: '' };
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.greet.refresh = stub().returns(message);
                participant.refresh();
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.refresh);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'dj.jazzy.jeff@rapper.com/android123');
                assert.strictEqual(participant.protocolOutQueue[0].to, '');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
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
                    participant.greet.state = illegalStates[i];
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
                participant.greet.state =  greeter.STATE.AUX_UPFLOW;
                var members = ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                               'Saturn', 'Uranus', 'Neptune', 'Pluto'];
                participant.greet.askeMember.members = utils.clone(members);
                participant.greet.cliquesMember.members = utils.clone(members);
                var message = { message: "Pluto's not a planet any more!!",
                                members: ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                                          'Saturn', 'Uranus', 'Neptune'],
                                dest: 'Mercury' };
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                sandbox.stub(participant.greet, 'start').returns(message);
                var keepMembers = ['Mercury', 'Venus', 'Earth', 'Mars', 'Jupiter',
                                   'Saturn', 'Uranus', 'Neptune'];
                participant.fullRefresh(keepMembers);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.start);
                sinon.assert.calledWith(participant.greet.start,
                                        ['Mercury', 'Venus', 'Mars', 'Jupiter',
                                         'Saturn', 'Uranus', 'Neptune']);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.deepEqual(participant.protocolOutQueue[0].message, message);
                assert.strictEqual(participant.protocolOutQueue[0].from, 'Earth');
                assert.strictEqual(participant.protocolOutQueue[0].to, 'Mercury');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.strictEqual(participant.greet.state, greeter.STATE.INIT_UPFLOW);
            });

            it('refresh by excluding last peer --> quit()', function() {
                var participant = new ns.ProtocolHandler('chingachgook@mohicans.org/android123',
                                                         'Last of the Mohicans',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state =  greeter.STATE.AUX_UPFLOW;
                var members = ['chingachgook@mohicans.org/android123',
                               'uncas@mohicans.org/ios1234'];
                participant.members = members;
                participant.greet.askeMember.members = utils.clone(members);
                participant.greet.cliquesMember.members = utils.clone(members);
                var message = {message: "The last of us!",
                               members: ['chingachgook@mohicans.org/android123'],
                               dest: ''};
                sandbox.stub(participant.greet, 'start').returns(message);
                sandbox.stub(participant, 'quit');
                participant.fullRefresh(['uncas@mohicans.org/ios1234']);
                sinon_assert.calledOnce(participant.greet.start);
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
                participant.greet.state =  greeter.STATE.AUX_DOWNFLOW;
                sandbox.stub(participant, 'refresh');
                participant.recover();
                sinon_assert.calledOnce(participant.refresh);
                assert.strictEqual(participant.greet.recovering, true);
            });

            it('full recover', function() {
                var participant = new ns.ProtocolHandler('beatrix@kiddo.com/android123',
                                                         'Kill Bill',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state =  greeter.STATE.AUX_UPFLOW;
                sandbox.stub(participant.greet, 'discardAuthentications');
                sandbox.stub(participant, 'fullRefresh');
                participant.recover();
                sinon_assert.calledOnce(participant.greet.discardAuthentications);
                sinon_assert.calledOnce(participant.fullRefresh);
                assert.strictEqual(participant.greet.recovering, true);
            });

            it('recover members to keep', function() {
                var participant = new ns.ProtocolHandler('beatrix@kiddo.com/android123',
                                                         'Kill Bill',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.state =  greeter.STATE.AUX_DOWNFLOW;
                var message = { message: "You're dead!",
                                dest: '' };
                participant.greet.askeMember.members = ['beatrix@kiddo.com/android123',
                                                        'vernita@green.com/outlook4711',
                                                        'o-ren@ishi.jp/ios1234'];
                sandbox.stub(participant.greet, 'discardAuthentications');
                sandbox.stub(participant, 'exclude');
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.recover(['beatrix@kiddo.com/android123', 'o-ren@ishi.jp/ios1234']);
                sinon_assert.calledOnce(participant.greet.discardAuthentications);
                sinon_assert.calledOnce(participant.exclude);
                assert.strictEqual(participant.greet.recovering, true);
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
                participant.greet.state = greeter.STATE.READY;
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
                participant.greet.state = greeter.STATE.READY;
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
                participant.greet.state = greeter.STATE.INIT_DOWNFLOW;
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
                participant.greet.state = greeter.STATE.READY;
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
                participant.greet.state = greeter.STATE.READY;
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
                participant.greet.state = greeter.STATE.AUX_DOWNFLOW;
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
                participant.greet.state = greeter.STATE.READY;
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
                var message = { message: 'dummy',
                                from: 'a.dumbledore@hogwarts.ac.uk/android123' };
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

            it('on greet message', function() {
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                var groupKey = _td.GROUP_KEY.substring(0, 16);
                participant.greet.cliquesMember.groupKey = groupKey;
                var message = { message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                                from: 'bar@baz.nl/blah123' };
                sandbox.stub(codec, 'categoriseMessage').returns(
                        { category: codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                          content: 'foo' });
                sandbox.stub(codec, 'decodeGreetMessage').returns(_td.DOWNFLOW_MESSAGE_STRING);
                sandbox.stub(participant.greet, 'processMessage').returns(
                        { decodedMessage: _td.DOWNFLOW_MESSAGE_STRING,
                          newState: greeter.STATE.READY });
                sandbox.stub(participant.greet, 'getEphemeralPubKey').returns(_td.ED25519_PUB_KEY);
                sandbox.stub(participant.greet, 'getEphemeralPrivKey').returns(_td.ED25519_PRIV_KEY);
                sandbox.stub(participant.greet, 'getMembers').returns([]);
                sandbox.stub(participant.greet, 'getEphemeralPubKeys').returns([]);
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(codec.decodeGreetMessage);
                sinon_assert.calledOnce(participant.greet.processMessage);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0].message, _td.DOWNFLOW_MESSAGE_STRING);
                assert.strictEqual(participant.protocolOutQueue[0].from, '2');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });

            it('downflow message with invalid session auth', function() {
                var message = { source: '5', dest: '',
                                messageType: greeter.MESSAGE_TYPE.INIT_PARTICIPANT_DOWN,
                                members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['5*4*3*2*G', '5*4*3*1*G', '5*4*2*1*G',
                                            '5*3*2*1*G', '4*3*2*1*G'],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.ProtocolHandler('2', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                sandbox.stub(codec, 'categoriseMessage').returns(
                        { category: codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                          content: 'foo' });
                sandbox.stub(codec, 'decodeGreetMessage').returns(_td.DOWNFLOW_MESSAGE_STRING);
                sandbox.spy(participant, 'quit');
                sandbox.stub(participant.greet, 'processMessage')
                        .throws(new Error('Session authentication by member 5 failed.'));
                sandbox.stub(participant.greet, 'getEphemeralPrivKey').returns(_td.ED25519_PRIV_KEY);
                sandbox.stub(participant.greet, 'getEphemeralPubKey').returns(_td.ED25519_PUB_KEY);
                sandbox.stub(participant.greet, 'quit').returns(
                        { dest: '',
                          source: participant.id,
                          messageType: greeter.MESSAGE_TYPE.QUIT_DOWN });
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.processMessage(message);
                assert.strictEqual(codec.categoriseMessage.callCount, 1);
                assert.strictEqual(codec.decodeGreetMessage.callCount, 1);
                assert.strictEqual(participant.greet.processMessage.callCount, 1);
                assert.strictEqual(participant.greet.getEphemeralPrivKey.callCount, 3);
                assert.strictEqual(participant.greet.getEphemeralPubKey.callCount, 4);
                assert.strictEqual(codec.encodeGreetMessage.callCount, 1);
                // To send two messages.
                assert.lengthOf(participant.protocolOutQueue, 2);
                assert.lengthOf(participant.uiQueue, 0);
                // An error message.
                var outMessage = participant.protocolOutQueue[0];
                assert.strictEqual(outMessage.message,
                                   '?mpENC Error:Ppt8GIrMisvCt0epOcOszUrpweZ5yXwnovrd+3zXZ9tF/4kd8gaV42fb9Q3psB1/z8Dftr3Ai7NOVjHHSlqrCQ==:from "2":TERMINAL:Session authentication by member 5 failed.');
                assert.strictEqual(outMessage.from, participant.id);
                assert.strictEqual(outMessage.to, '');
                // And a QUIT message.
                assert.strictEqual(participant.quit.callCount, 1);
                assert.strictEqual(participant.greet.quit.callCount, 1);
                outMessage = participant.protocolOutQueue[1];
                assert.strictEqual(outMessage.message.source, participant.id);
                assert.strictEqual(outMessage.from, participant.id);
                assert.strictEqual(outMessage.message.dest, '');
                assert.strictEqual(outMessage.to, '');
                assert.strictEqual(outMessage.message.messageType, greeter.MESSAGE_TYPE.QUIT_DOWN);
            });

            it('on own greet message with flushed ephemeralPubKeys', function() {
                var participant = new ns.ProtocolHandler('1', 'foo',
                                                         _td.ED25519_PRIV_KEY,
                                                         _td.ED25519_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.sessionKeyStore = _dummySessionStore();
                participant.greet.cliquesMember.groupKey = _td.GROUP_KEY.substring(0, 16);
                participant.greet.askeMember.ephemeralPubKeys = [];
                participant.greet.askeMember.ephemeralPubKey = _td.ED25519_PUB_KEY;
                var message = { message: _td.DOWNFLOW_MESSAGE_PAYLOAD,
                                from: '1' };
                sandbox.stub(codec, 'categoriseMessage').returns(
                        { category: codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                          content: 'foo' });
                sandbox.stub(codec, 'decodeGreetMessage').returns(_td.DOWNFLOW_MESSAGE_STRING);
                sandbox.stub(participant.greet, 'processMessage').returns(
                        { decodedMessage: _td.DOWNFLOW_MESSAGE_STRING,
                          newState: greeter.STATE.READY });
                sandbox.stub(codec, 'encodeGreetMessage', _echo);
                participant.processMessage(message);
                sinon_assert.calledOnce(codec.categoriseMessage);
                sinon_assert.calledOnce(codec.decodeGreetMessage);
                assert.strictEqual(codec.decodeGreetMessage.getCall(0).args[1], _td.ED25519_PUB_KEY);
                sinon_assert.calledOnce(participant.greet.processMessage);
                sinon_assert.calledOnce(codec.encodeGreetMessage);
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
                participant.greet.state = greeter.STATE.READY;
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
    });
});
