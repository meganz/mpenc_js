/**
 * @fileOverview
 * Test of the `mpenc/greet/cliques` module.
 */

/*
 * Created: 20 Jan 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/greet/cliques",
    "mpenc/helper/utils",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
    "asmcrypto",
], function(ns, utils, chai, sinon_assert, sinon_sandbox, sinon_spy, asmCrypto) {
    "use strict";
    var assert = chai.assert;

    var _echo = function(x) { return x; };

    describe("module level", function() {
        describe('_computeKeyDebug()', function() {
            it('should multiply debug with base point if no key given', function() {
                assert.strictEqual(ns._computeKeyDebug('1'), '1*G');
                assert.strictEqual(ns._computeKeyDebug('2'), '2*G');
            });

            it('should multiply debug priv key with intermediate key', function() {
                assert.deepEqual(ns._computeKeyDebug('1', '2*G'), '1*2*G');
                assert.deepEqual(ns._computeKeyDebug('2', '3*4*5*G'), '2*3*4*5*G');
            });
        });
    });

    describe('CliquesMember class', function() {
        describe('constructor', function() {
            it('simple CliquesMember constructor', function() {
                var participant = new ns.CliquesMember('4');
                assert.strictEqual(participant.id, '4');
                assert.strictEqual(participant.privKeyId, 0);
            });
        });

        describe('#_setKeys() method', function() {
            it('update local key state', function() {
                var numMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.privKey = _PRIV_KEY();
                participant._debugPrivKey = '3';
                var intKeys = [];
                var debugIntKeys = ['2*3*4*5*G', '1*3*4*5*G', '1*2*4*5*G',
                                    '1*2*3*5*G', '1*2*3*4*G'];
                for (var i = 1; i <= numMembers; i++) {
                    participant.members.push(i.toString());
                    intKeys.push(_PRIV_KEY());
                    debugIntKeys.push(i.toString());
                }
                participant._setKeys(intKeys, debugIntKeys);
                assert.deepEqual(participant.intKeys, intKeys);
                assert.deepEqual(participant._debugIntKeys, debugIntKeys);
                assert.notStrictEqual(participant.groupKey, _td.C25519_PRIV_KEY);
                assert.strictEqual(participant._debugGroupKey, '3*1*2*4*5*G');
            });
        });

        describe('#_renewPrivKey() method', function() {
            it('reniewing private key and int keys', function() {
                var numMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.privKey = _PRIV_KEY();
                participant._debugPrivKey = '3';
                participant._debugIntKeys = ['2*3*4*5*G', '1*3*4*5*G', '1*2*4*5*G',
                                             '1*2*3*5*G', '1*2*3*4*G'];
                participant.intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                }
                var response = participant._renewPrivKey();
                assert.notStrictEqual(participant.privKey, _td.C25519_PRIV_KEY);
                assert.strictEqual(participant.privKeyId, 1);
                assert.strictEqual(participant._debugPrivKey, "3'");
                assert.notDeepEqual(response.cardinalKey, _td.C25519_PRIV_KEY);
                assert.strictEqual(response.cardinalDebugKey, "3'*3*1*2*4*5*G");
                for (var i = 0; i < participant.intKeys.length; i++) {
                    if (i === 2) {
                        assert.strictEqual(participant._debugIntKeys[i],
                                           "3*1*2*4*5*G");
                    } else {
                        assert.strictEqual(participant._debugIntKeys[i].substring(0, 2),
                                           "3'");
                    }
                }
            });
        });

        describe('#ika() method', function() {
            it('start the IKA', function() {
                var participant = new ns.CliquesMember('1');
                sinon_sandbox.spy(participant, 'upflow');
                var otherMembers = ['2', '3', '4', '5', '6'];
                participant.ika(otherMembers);
                sinon_assert.calledOnce(participant.upflow);
            });

            it('start the IKA without members', function() {
                var participant = new ns.CliquesMember('1');
                assert.throws(function() { participant.ika([]); },
                              'No members to add.');
            });
        });

        describe('#ikaFullRefresh() method', function() {
            it('fully refresh using ika', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                participant._debugIntKeys = [];
                participant.privKeyId = 42;
                participant.privKey = _PRIV_KEY();
                participant.goupKey = _PRIV_KEY();
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant._debugIntKeys.push(i.toString());
                }
                var oldTs = participant.keyTimestamp;
                var message = participant.ikaFullRefresh();
                assert.ok(participant.keyTimestamp > oldTs);
                assert.notStrictEqual(participant.privKey, _td.C25519_PRIV_KEY);
                assert.strictEqual(participant.privKeyId, 43);
                assert.strictEqual(message.dest, '1');
                assert.deepEqual(message.members, ['3', '1', '2', '4', '5']);
            });
        });

        describe('#upflow() method', function() {
            it('ika upflow, no previous messages', function() {
                var participant = new ns.CliquesMember('1');
                var members = ['1', '2', '3', '4', '5', '6'];
                var startMessage = new ns.CliquesMessage();
                startMessage.members = members;
                startMessage.agreement = 'ika';
                startMessage.flow = 'upflow';
                var oldTs = participant.keyTimestamp;
                var newMessage = participant.upflow(startMessage);
                assert.ok(participant.keyTimestamp > oldTs);
                assert.deepEqual(participant.members, members);
                assert.deepEqual(newMessage.members, members);
                assert.strictEqual(_tu.keyBits(participant.privKey, 8), 256);
                assert.strictEqual(newMessage.agreement, 'ika');
                assert.strictEqual(newMessage.flow, 'upflow');
                assert.lengthOf(newMessage.intKeys, 2);
                assert.strictEqual(newMessage.intKeys[0], null);
                assert.strictEqual(_tu.keyBits(newMessage.intKeys[newMessage.intKeys.length - 1], 8), 256);
                assert.strictEqual(newMessage.source, '1');
                assert.strictEqual(newMessage.dest, '2');
            });

            it('ika upflow duplicates in member list', function() {
                var participant = new ns.CliquesMember('1');
                var members = ['3', '1', '2', '3', '4', '5', '6'];
                var startMessage = new ns.CliquesMessage();
                startMessage.members = members;
                assert.throws(function() { participant.upflow(startMessage); },
                              'Duplicates in member list detected!');
            });

            it('ika upflow on completed upflow', function() {
                var participant = new ns.CliquesMember('1');
                var members = ['1', '2', '3', '4', '5'];
                var message = new ns.CliquesMessage();
                message.members = members;
                message.debugKeys = ['2*3*4*5*G', '1*3*4*5*G', '1*2*4*5*G',
                                     '1*2*3*5*G', '1*2*3*4*G', 'foo'];
                message.intKeys = [];
                for (var i = 0; i < 6; i++) {
                    message.intKeys.push(_PRIV_KEY());
                }
                assert.throws(function() { participant.upflow(message); },
                              'Too many intermediate keys on CLIQUES upflow!');
            });

            it('ika upflow, for all members', function() {
                var numMembers = 5;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    participants.push(new ns.CliquesMember(i.toString()));
                }
                var message = new ns.CliquesMessage();
                message.members = members;
                message.agreement = 'ika';
                message.flow = 'upflow';
                for (var i = 0; i < numMembers - 1; i++) {
                    message = participants[i].upflow(message);
                    assert.deepEqual(participants[i].members, members);
                    assert.strictEqual(_tu.keyBits(participants[i].privKey, 8), 256);
                    assert.strictEqual(message.agreement, 'ika');
                    assert.strictEqual(message.flow, 'upflow');
                    assert.lengthOf(message.intKeys, i + 2);
                    assert.strictEqual(_tu.keyBits(message.intKeys[i + 1], 8), 256);
                    if (i === 0) {
                        assert.strictEqual(message.intKeys[0], null);
                    } else {
                        assert.strictEqual(_tu.keyBits(message.intKeys[0], 8), 256);
                    }
                    assert.strictEqual(message.source, members[i]);
                    assert.strictEqual(message.dest, members[i + 1]);
                }

                // The last member behaves differently.
                message = participants[numMembers - 1].upflow(message);
                assert.deepEqual(participants[i].members, members);
                assert.strictEqual(_tu.keyBits(participants[i].privKey, 8), 256);
                assert.strictEqual(message.agreement, 'ika');
                assert.strictEqual(message.flow, 'downflow');
                assert.lengthOf(message.intKeys, numMembers);
                assert.strictEqual(_tu.keyBits(message.intKeys[0], 8), 256);
                assert.strictEqual(_tu.keyBits(message.intKeys[numMembers - 1], 8), 256);
                // Last one goes to all.
                assert.strictEqual(message.source, members[numMembers - 1]);
                assert.strictEqual(message.dest, '');
            });

            it('ika upflow, for full refresh', function() {
                var participant = new ns.CliquesMember('2');
                var members = ['1', '2', '3', '4', '5'];
                participant.members = members;
                participant._debugIntKeys = ['2*3*4*5*G', '1*3*4*5*G', '1*2*4*5*G',
                                             '1*2*3*5*G', '1*2*3*4*G'];
                participant.privKey = _PRIV_KEY();
                participant.privKeyId = 41;
                participant._debugPrivKey = '2';
                    var startMessage = {
                    members: ['1', '2', '3', '4', '5'],
                    agreement: 'ika',
                    flow: 'upflow',
                    intKeys: [null, 'foo'],
                    debugKeys: [null, '1*G']
                };
                var oldTs = participant.keyTimestamp;
                var newMessage = participant.upflow(startMessage);
                assert.ok(participant.keyTimestamp > oldTs);
                assert.strictEqual(participant.privKeyId, 42);
                assert.deepEqual(participant.members, members);
                assert.deepEqual(newMessage.members, members);
                assert.strictEqual(_tu.keyBits(participant.privKey, 8), 256);
                assert.strictEqual(newMessage.agreement, 'ika');
                assert.strictEqual(newMessage.flow, 'upflow');
                assert.lengthOf(newMessage.intKeys, 3);
                assert.deepEqual(newMessage.debugKeys, ['2*G', '1*G', '2*1*G']);
                assert.strictEqual(_tu.keyBits(newMessage.intKeys[0], 8), 256);
                assert.strictEqual(_tu.keyBits(newMessage.intKeys[newMessage.intKeys.length - 1], 8), 256);
                assert.strictEqual(newMessage.source, '2');
                assert.strictEqual(newMessage.dest, '3');
            });
        });

        describe('#downflow() method', function() {
            it('ika downflow duplicates in member list', function() {
                var members = ['3', '1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = ['1', '2', '3', '4', '5'];
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.members = members;
                assert.throws(function() { participant.downflow(broadcastMessage); },
                              'Duplicates in member list detected!');
            });

            it('ika downflow member list mismatch', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = ['1', '2', '3', '4'];
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.members = members;
                broadcastMessage.agreement = 'ika';
                assert.throws(function() { participant.downflow(broadcastMessage); },
                              'Member list mis-match in CLIQUES protocol');
            });

            it('ika downflow intKey list number mismatch', function() {
                var members = ['1', '2', '3', '4', '5'];
                var messageKeys = [];
                for (var i = 1; i <= 4; i++) {
                    messageKeys.push(_PRIV_KEY());
                }
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant.privKey = _PRIV_KEY();
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'downflow';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
                broadcastMessage.debugKeys = utils.clone(members);
                assert.throws(function() { participant.downflow(broadcastMessage); },
                              'Mis-match intermediate key number for CLIQUES downflow.');
            });

            it('ika downflow message process', function() {
                var numMembers = 5;
                var members = [];
                var messageKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    messageKeys.push(_PRIV_KEY());
                }
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant.privKey = _PRIV_KEY();
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'downflow';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
                broadcastMessage.debugKeys = utils.clone(members);
                participant.downflow(broadcastMessage);
                assert.strictEqual(participant.intKeys, messageKeys);
                assert.strictEqual(_tu.keyBits(participant.groupKey, 8), 256);
                assert.notStrictEqual(participant.groupKey, _td.C25519_PRIV_KEY);
            });

            it('ika duplicate downflow message process', function() {
                var numMembers = 5;
                var members = [];
                var messageKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    messageKeys.push(_PRIV_KEY());
                }
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant.privKey = _PRIV_KEY();
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'downflow';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
                broadcastMessage.debugKeys = utils.clone(members);
                participant.downflow(broadcastMessage);
                var prevGroupKey = participant.groupKey;
                participant.downflow(broadcastMessage);
                assert.strictEqual(participant.groupKey, prevGroupKey);
            });
        });

        describe('#akaJoin() method', function() {
            it('join empty member list using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant._debugGroupKey = '1*2*3*4*5*G';
                assert.throws(function() { participant.akaJoin([]); },
                              'No members to add.');
            });

            it('join duplicate member list using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant._debugGroupKey = '1*2*3*4*5*G';
                assert.throws(function() { participant.akaJoin(['2']); },
                              'Duplicates in member list detected!');
            });

            it('join a member using aka', function() {
                var numMembers = 5;
                var members = [];
                var participant = new ns.CliquesMember('3');
                participant.privKey = _PRIV_KEY();
                participant._debugPrivKey = '3';
                participant.groupKey = _PRIV_KEY();
                participant._debugGroupKey = '3*1*2*4*5*G';
                participant._debugIntKeys = ['2*3*4*5*G', '1*3*4*5*G', '1*2*4*5*G',
                                             '1*2*3*5*G', '1*2*3*4*G'];
                participant.intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant.members.push(i.toString());
                }
                var oldTs = participant.keyTimestamp;
                var message = participant.akaJoin(['6']);
                assert.ok(participant.keyTimestamp > oldTs);
                assert.lengthOf(message.members, 6);
                assert.lengthOf(message.intKeys, 6);
                assert.strictEqual(_tu.keyBits(participant.privKey, 8), 256);
                assert.notDeepEqual(participant.privKey, _td.C25519_PRIV_KEY);
                assert.strictEqual(message.agreement, 'aka');
                assert.strictEqual(message.flow, 'upflow');
                for (var i = 0; i < message.debugKeys.length; i++) {
                    assert.ok(message.debugKeys[i].indexOf("3*") >= 0);
                    if (i === 2) {
                        assert.ok(message.debugKeys[i].indexOf("3'*") < 0);
                    } else {
                        assert.ok(message.debugKeys[i].indexOf("3'*") >= 0);
                    }
                }
                assert.strictEqual(_tu.keyBits(message.intKeys[0], 8), 256);
                assert.strictEqual(_tu.keyBits(message.intKeys[5], 8), 256);
                assert.strictEqual(message.source, '3');
                assert.strictEqual(message.dest, '6');
                // Upflow for the new guy '6'.
                var newParticipant = new ns.CliquesMember('6');
                message = newParticipant.upflow(message);
                assert.strictEqual(newParticipant._debugGroupKey, "6*3'*3*1*2*4*5*G");
                // Downflow for initiator and new guy.
                participant.downflow(message);
                assert.strictEqual(participant._debugGroupKey, "3'*6*3*1*2*4*5*G");
                newParticipant.downflow(message);
                assert.deepEqual(participant.groupKey, newParticipant.groupKey);
            });
        });

        describe('#akaExclude() method', function() {
            it('exclude empty member list using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant._debugGroupKey = '1*2*3*4*5*G';
                assert.throws(function() { participant.akaExclude([]); },
                              'No members to exclude.');
            });

            it('exclude non existing member using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant._debugGroupKey = '1*2*3*4*5*G';
                assert.throws(function() { participant.akaExclude(['1', '7']); },
                              'Members list to exclude is not a sub-set of previous members!');
            });

            it('exclude self using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                participant._debugGroupKey = '1*2*3*4*5*G';
                assert.throws(function() { participant.akaExclude(['3', '5']); },
                              'Cannot exclude mysefl.');
            });

            it('exclude members using aka', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                participant._debugIntKeys = [];
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant._debugIntKeys.push(i.toString());
                    participant.privKey = _PRIV_KEY();
                    participant.goupKey = _PRIV_KEY();
                }
                sinon_sandbox.spy(utils, 'sha256');
                // Exclude members '1' and '4'.
                var thenMembers = ['2', '3', '5'];
                participant._debugGroupKey = '1*2*3*4*5*G';
                var oldTs = participant.keyTimestamp;
                var message = participant.akaExclude(['1', '4']);
                assert.ok(participant.keyTimestamp > oldTs);
                assert.deepEqual(message.members, thenMembers);
                assert.deepEqual(participant.members, thenMembers);
                assert.notDeepEqual(participant.privKey, _td.C25519_PRIV_KEY);
                assert.notDeepEqual(participant.groupKey, _td.C25519_PRIV_KEY);
                assert.notDeepEqual(participant.groupKey, undefined);
                sinon_assert.calledOnce(utils.sha256);
            });
        });

        describe('#akaRefresh() method', function() {
            it('refresh own private key using aka', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                participant._debugIntKeys = [];
                participant.privKey = _PRIV_KEY();
                participant.goupKey = _PRIV_KEY();
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant._debugIntKeys.push(i.toString());
                }
                var chkGroupKey = participant.groupKey;
                var oldTs = participant.keyTimestamp;
                var message = participant.akaRefresh();
                assert.ok(participant.keyTimestamp > oldTs);
                assert.notStrictEqual(participant.privKey, _td.C25519_PRIV_KEY);
                assert.notStrictEqual(participant.groupKey, chkGroupKey);
                assert.strictEqual(participant.privKeyId, 1);
                assert.strictEqual(message.dest, '');
            });
        });

        describe('#akaQuit() method', function() {
            it('not a member any more', function() {
                var participant = new ns.CliquesMember('3');
                participant.members = ['1', '2'];
                assert.throws(function() { participant.akaQuit(); },
                              'Not participating.');
            });

            it('simple test', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                participant._debugIntKeys = [];
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant._debugIntKeys.push(i.toString());
                    participant.privKey = _PRIV_KEY();
                    participant.goupKey = _PRIV_KEY();
                }
                participant.akaQuit();
                assert.strictEqual(participant.keyTimestamp, null);
                assert.deepEqual(participant.members, ['1', '2', '4', '5']);
                assert.deepEqual(participant.intKeys, []);
                assert.deepEqual(participant._debugIntKeys, []);
                assert.deepEqual(participant.privKey, null);
            });
        });

        describe('whole ika', function() {
            it('whole flow for 5 ika members, 2 joining, 2 others leaving, refresh, full refresh', function() {
                var numMembers = 5;
                var initiator = 0;
                var members = [];
                var participants = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    participants.push(new ns.CliquesMember(i.toString()));
                }
                var otherMembers = [];
                for (var i = 2; i <= numMembers; i++) {
                    otherMembers.push(i.toString());
                }
                // IKA start.
                var message = participants[initiator].ika(otherMembers);

                // IKA upflow.
                while (message.flow === 'upflow') {
                    if (message.dest !== '') {
                        var nextId = message.members.indexOf(message.dest);
                        message = participants[nextId].upflow(message);
                    } else {
                        assert.ok(false,
                                  "This shouldn't happen, something's seriously dodgy!");
                    }
                }

                // IKA downflow for all.
                var keyCheck = null;
                for (var i = 0; i < numMembers; i++) {
                    var participant = participants[i];
                    participant.downflow(message);
                    assert.strictEqual(participant.id, members[i]);
                    assert.deepEqual(participant.members, members);
                    if (!keyCheck) {
                        keyCheck = participant.groupKey;
                    } else {
                        assert.strictEqual(participant.groupKey, keyCheck);
                    }
                }

                // AKA to join two new guys.
                var newMembers = ['6', '7'];
                for (var i = 0; i < newMembers.length; i++) {
                    participants.push(new ns.CliquesMember(newMembers[i]));
                }

                // '4' starts AKA for join.
                message = participants[3].akaJoin(newMembers);
                // AKA upflow for join.
                while (message.flow === 'upflow') {
                    if (message.dest !== '') {
                        var nextId = message.members.indexOf(message.dest);
                        message = participants[nextId].upflow(message);
                    } else {
                        assert.ok(false,
                                  "This shouldn't happen, something's seriously dodgy!");
                    }
                }

                // AKA downflow for join.
                keyCheck = null;
                for (var i = 0; i < message.members.length; i++) {
                    var member = message.members[i];
                    var participant = participants[i];
                    participant.downflow(message);
                    assert.strictEqual(participant.id, member);
                    assert.deepEqual(participant.members, message.members);
                    if (!keyCheck) {
                        keyCheck = participant.groupKey;
                    } else {
                        assert.deepEqual(participant.groupKey, keyCheck);
                    }
                }

                // '3' excludes some members.
                var toExclude = ['1', '4'];
                for (var i = 0; i < toExclude.length; i++) {
                    var delIndex = members.indexOf(toExclude[i]);
                    members.splice(delIndex, 1);
                    participants.splice(delIndex, 1);
                }
                message = participants[2].akaExclude(toExclude);
                members = message.members;

                // AKA downflow for exclude.
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    var participant = participants[i];
                    if (message.members.indexOf(participant.id) < 0) {
                        assert.throws(function() { participant.downflow(message); },
                                      'Not in members list, must be excluded.');
                        continue;
                    }
                    participant.downflow(message);
                    assert.deepEqual(participant.members, message.members);
                    if (!keyCheck) {
                        keyCheck = participant.groupKey;
                    } else {
                        assert.deepEqual(participant.groupKey, keyCheck);
                    }
                }

                // '2' initiates a key refresh.
                var oldGroupKey = participants[0].groupKey;
                message = participants[0].akaRefresh();
                assert.notStrictEqual(participants[0].groupKey, oldGroupKey);

                // AKA downflow for refresh.
                keyCheck = null;
                for (var i = 0; i < participants.length; i++) {
                    if (message.members.indexOf(participants[i].id) >= 0) {
                        participants[i].downflow(message);
                        assert.deepEqual(participants[i].members, message.members);
                        if (!keyCheck) {
                            keyCheck = participants[i].groupKey;
                        } else {
                            assert.strictEqual(participants[i].groupKey, keyCheck);
                        }
                    }
                }

                // '5' starts a full refresh.
                var oldPrivKey = participants[2].privKey;
                message = participants[2].ikaFullRefresh();
                assert.notStrictEqual(participants[2].privKey, oldPrivKey);
                // Sort participants.
                var tempParticipants = [];
                for (var i = 0; i < message.members.length; i++) {
                    var index = members.indexOf(message.members[i]);
                    tempParticipants.push(participants[index]);
                }
                participants = tempParticipants;
                members = message.members;

                // Upflow for full refresh.
                while (message.flow === 'upflow') {
                    if (message.dest !== '') {
                        var nextId = message.members.indexOf(message.dest);
                        oldPrivKey = participants[nextId].privKey;
                        message = participants[nextId].upflow(message);
                        assert.notStrictEqual(participants[nextId].privKey, oldPrivKey);
                    } else {
                        assert.ok(false,
                                  "This shouldn't happen, something's seriously dodgy!");
                    }
                }

                // Downflow for full refresh.
                keyCheck = null;
                for (var i = 0; i < numMembers; i++) {
                    var participant = participants[i];
                    participant.downflow(message);
                    assert.strictEqual(participant.id, members[i]);
                    assert.deepEqual(participant.members, members);
                    if (!keyCheck) {
                        keyCheck = participant.groupKey;
                    } else {
                        assert.strictEqual(participant.groupKey, keyCheck);
                    }
                }
            });
        });
    });

    /**
     * Returns a fresh copy of the private key constant, protected from "cleaning".
     * @returns Array of words.
     */
    function _PRIV_KEY() {
        return utils.clone(_td.C25519_PRIV_KEY);
    }
});
