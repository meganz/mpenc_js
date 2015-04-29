/**
 * @fileOverview
 * Test of the `mpenc/handler` module.
 */

/*
 * Created: 4 Mar 2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/message",
    "mpenc/version",
    "mpenc/greet/keystore",
    "mpenc/greet/greeter",
    "asmcrypto",
    "jodid25519",
    "megalogger",
    "chai",
    "sinon/sandbox",
], function(ns, utils, codec, messages, version, keystore, greeter,
            asmCrypto, jodid25519, MegaLogger,
            chai, sinon_sandbox) {
    "use strict";

    var assert = chai.assert;

    MegaLogger._logRegistry.handler.options.isEnabled = false;
    MegaLogger._logRegistry.assert.options.isEnabled = false;

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

    function _stripProtoFromMessage(message) {
        var _PROTO_STRING = '?mpENC:';
        if (!message) {
            return null;
        }
        return atob(message.substring(_PROTO_STRING.length, message.length - 1));
    }

    function _getPayload(message, senderParticipant) {
        if (message && senderParticipant) {
            var content = codec.decodeWirePacket(_stripProtoFromMessage(message.message)).content;
            var sessionID = senderParticipant._sessionKeyStore.sessionIDs[0];
            var groupKey = sessionID
                         ? senderParticipant._sessionKeyStore.sessions[sessionID].groupKeys[0]
                         : undefined;
            return greeter.decodeGreetMessage(content,
                                              senderParticipant.greet.getEphemeralPubKey(),
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
            assert.strictEqual(participants[initiator].greet.state, greeter.STATE.INIT_UPFLOW);

            console.log('Upflow for start at ' + Math.round(Date.now() / 1000 - startTime));
            // Upflow.
            while (message && payload.dest !== '') {
                var nextId = payload.members.indexOf(payload.dest);
                participants[nextId].processMessage(message);
                message = participants[nextId].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                                    if (payload.dest === '') {
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.INIT_DOWNFLOW);
                } else {
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.INIT_UPFLOW);
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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.INIT_DOWNFLOW);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
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
            participants[1].include(newMembers);
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
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.AUX_DOWNFLOW);
                } else {
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.AUX_UPFLOW);
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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.AUX_DOWNFLOW);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.AUX_DOWNFLOW);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
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
                assert(uiMessage instanceof messages.Message);
                assert.strictEqual(uiMessage.secretData, 'Rock me Amadeus');
                assert.strictEqual(uiMessage.author, '5');
            }

            console.log('Refreshing at ' + Math.round(Date.now() / 1000 - startTime));
            // '2' initiates a key refresh.
            var oldGroupKey = participants[0].greet.getGroupKey();
            var oldPrivKeyListLength = participants[0].greet.cliquesMember.privKeyList.length;
            participants[0].refresh();
            message = participants[0].protocolOutQueue.shift();
            payload = _getPayload(message, _getSender(message, participants, members));
            assert.lengthOf(participants[0].greet.cliquesMember.privKeyList, oldPrivKeyListLength + 1);
            assert.notStrictEqual(participants[0].greet.getGroupKey(), oldGroupKey);

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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.AUX_DOWNFLOW);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.notStrictEqual(participant.greet.getGroupKey(), oldGroupKey);
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
            }

            console.log('Recovering at ' + Math.round(Date.now() / 1000 - startTime));
            // '5' starts a full recovery.
            participants[2].greet.state = greeter.STATE.AUX_UPFLOW; // The glitch, where things got stuck.
            oldGroupKey = participants[2].greet.getGroupKey();
            var oldSigningKey = participants[2].greet.getEphemeralPrivKey();
            // Should do a fullRefresh()
            participants[2].recover();
            assert.strictEqual(participants[2].greet.recovering, true);
            message = participants[2].protocolOutQueue.shift();
            payload = _getPayload(message, _getSender(message, participants, members));
            assert.lengthOf(participants[2].greet.cliquesMember.privKeyList, 1);
            assert.strictEqual(participants[2].greet.getEphemeralPrivKey(), oldSigningKey);
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
                oldSigningKey = participants[nextId].greet.getEphemeralPrivKey();
                participants[nextId].processMessage(message);
                assert.strictEqual(participants[nextId].greet.recovering, true);
                assert.strictEqual(participants[nextId].greet.getEphemeralPrivKey(), oldSigningKey);
                message = participants[nextId].protocolOutQueue.shift();
                payload = _getPayload(message, _getSender(message, participants, members));
                if (payload.dest === '') {
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.INIT_DOWNFLOW);
                } else {
                    assert.strictEqual(participants[nextId].greet.state, greeter.STATE.INIT_UPFLOW);
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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                        assert.strictEqual(participant.greet.recovering, false);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.INIT_DOWNFLOW);
                        assert.strictEqual(participant.greet.recovering, true);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.notStrictEqual(participant.greet.getGroupKey(), oldGroupKey);
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
            assert.strictEqual(message.message, ns.PLAINTEXT_AUTO_RESPONSE);
            message = participants[1].protocolOutQueue.shift();
            assert.strictEqual(message.message, codec.encodeWirePacket(codec.MPENC_QUERY_MESSAGE));
            assert.strictEqual(message.from, '2');
            assert.strictEqual(message.to, '1');
            var uiMessage = participants[1].uiQueue.shift();
            assert.strictEqual(uiMessage.type, 'info');
            assert.strictEqual(uiMessage.message, 'Received unencrypted message, requesting encryption.');
            assert.strictEqual(participants[1].greet.state, greeter.STATE.NULL);

            // Process mpENC query response.
            participants[0].processMessage(message);
            message = participants[0].protocolOutQueue.shift();
            payload = _getPayload(message, participants[0]);
            assert.strictEqual(payload.source, '1');
            assert.strictEqual(payload.dest, '2');
            assert.strictEqual(payload.greetType, greeter.GREET_TYPE.INIT_INITIATOR_UP);
            assert.strictEqual(participants[0].greet.state, greeter.STATE.INIT_UPFLOW);

            // Process key agreement upflow.
            participants[1].processMessage(message);
            message = participants[1].protocolOutQueue.shift();
            payload = _getPayload(message, participants[1]);
            assert.strictEqual(payload.source, '2');
            assert.strictEqual(payload.dest, '');
            assert.strictEqual(payload.greetType, greeter.GREET_TYPE.INIT_PARTICIPANT_DOWN);
            assert.strictEqual(participants[1].greet.state, greeter.STATE.INIT_DOWNFLOW);

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
                    if (participant.greet.isSessionAcknowledged()) {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.INIT_DOWNFLOW);
                    }
                    assert.deepEqual(participant.greet.getMembers(), members);
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
                    keyCheck = participant.greet.getGroupKey();
                } else {
                    assert.strictEqual(participant.greet.getGroupKey(), keyCheck);
                }
                assert.ok(participant.greet.isSessionAcknowledged());
                assert.strictEqual(participant.greet.state, greeter.STATE.READY);
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
                        assert.strictEqual(participant.greet.state, greeter.STATE.QUIT);
                        assert.deepEqual(participant.greet.getMembers(), ['1']);
                    } else {
                        assert.strictEqual(participant.greet.state, greeter.STATE.READY);
                        assert.deepEqual(participant.greet.getMembers(), members);
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
            assert.strictEqual(participants[0].greet.state, greeter.STATE.QUIT);
            assert.strictEqual(message.greetType, greeter.GREET_TYPE.QUIT);
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
        assert.strictEqual(participants['1'].greet.state, greeter.STATE.INIT_UPFLOW);

        // Processing start/upflow message.
        participants['2'].processMessage(protocolMessage);
        protocolMessage = participants['2'].protocolOutQueue.shift();
        assert.strictEqual(participants['2'].greet.state, greeter.STATE.INIT_DOWNFLOW);

        // Process first downflow message.
        participants['1'].processMessage(protocolMessage);
        protocolMessage = participants['1'].protocolOutQueue.shift();
        assert.strictEqual(participants['1'].greet.state, greeter.STATE.READY);

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
        assert.strictEqual(participants['1'].greet.state, greeter.STATE.INIT_UPFLOW);

        // Processing start/upflow message.
        participants['2'].processMessage(protocolMessage);
        protocolMessage = participants['2'].protocolOutQueue.shift();
        assert.strictEqual(participants['2'].greet.state, greeter.STATE.INIT_DOWNFLOW);

        // This 'stateUpdatedCallback' will add a assert() to ensure that
        // the .greet.state is set to READY, after the protocolOutQueue got
        // a new message added (not before!)
        participants['1'].stateUpdatedCallback = function(h) {
            if(this.greet.state === greeter.STATE.READY) {
                assert.strictEqual(participants['1'].protocolOutQueue.length, 1);
            }
        };

        // Now process the first downflow message.
        // This will also trigger the .statusUpdateCallback, which will
        // guarantee that .protocolOutQueue contains exactly 1 message in
        // the queue.
        participants['1'].processMessage(protocolMessage);
        protocolMessage = participants['1'].protocolOutQueue.shift();
        assert.strictEqual(participants['1'].greet.state, greeter.STATE.READY);
        // We don't need this check anymore, let's remove it.
        participants['1'].stateUpdatedCallback = function(h) {};

        // Participant 2 should process the new protocolOut message.
        participants['2'].processMessage(protocolMessage);
        // Participant 2 is also ready.
        assert.strictEqual(participants['2'].greet.state, greeter.STATE.READY);

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

        assert(participants['2'].uiQueue[0] instanceof messages.Message);
        assert.strictEqual(participants['2'].uiQueue[0].secretData, "How you doin'?");
        assert.strictEqual(participants['2'].uiQueue[0].author, "1");
    });
});
