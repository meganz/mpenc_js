/**
 * @fileOverview
 * Test of the `mpenc/greet/cliques` module.
 */

/*
 * Created: 20 Jan 2014 Guy K. Kloss <gk@mega.co.nz>
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
        describe('_computeKeyList()', function() {
            var expected = ['hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
                            'Y4FAHmzbDX8htpo8pGWcBjNFGXF1V2VLe59Co44n0SQ=',
                            'o+vGVpHhzAfr8tD9vkPAmE22lb63GdeTRdSf0e/Qx1U=',
                            'toayzMw4lDk+4eqSccjLxp7VtABqt69ZNIJDHV/Evz8='];

            it('vanilla cases with intKey', function() {
                var intKey = _td.C25519_PUB_KEY;
                var tests = [[_td.C25519_PRIV_KEY_B],
                             [_td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B],
                             [_td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B]];
                for (var i = 0; i < tests.length; i++) {
                    assert.strictEqual(btoa(ns._computeKeyList(tests[i], intKey)),
                                       expected[i + 1]);
                }
            });

            it('without intKey', function() {
                var tests = [[_td.C25519_PRIV_KEY_B],
                             [_td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B],
                             [_td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B, _td.C25519_PRIV_KEY_B]];
                for (var i = 0; i < tests.length; i++) {
                    assert.strictEqual(btoa(ns._computeKeyList(tests[i])),
                                       expected[i]);
                }
            });
        });

        describe('deriveGroupKey()', function() {
            var baseCase = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" +
                           "\x0b\x0b\x0b\x0b\x0b\x0b";
            it("sanity check", function() {
                // Test Case 3 from RFC 5869
                assert.strictEqual(btoa(ns.deriveGroupKey(baseCase, "")),
                    btoa("\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31" +
                         "\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d"));
            });
            it("base case", function() {
                // Test against Python:
                // >>> from hmac import HMAC; from hashlib import sha256
                // >>> hmac = lambda *args: HMAC(*args, digestmod=sha256)
                // >>> hmac(hmac(b"", b"\x0b"*22).digest(), b"mpenc group key\x01").hexdigest()
                // 'c9cc6b03feceadd360859a46932477ca924cc646be0d6f07dc8c4e2d49bd6301'
                assert.strictEqual(btoa(ns.deriveGroupKey(baseCase)),
                    btoa("\xc9\xcc\x6b\x03\xfe\xce\xad\xd3\x60\x85\x9a\x46\x93\x24\x77\xca" +
                         "\x92\x4c\xc6\x46\xbe\x0d\x6f\x07\xdc\x8c\x4e\x2d\x49\xbd\x63\x01"));
            });
        });
    });

    describe('CliquesMember class', function() {
        describe('constructor', function() {
            it('simple CliquesMember constructor', function() {
                var participant = new ns.CliquesMember('4');
                assert.strictEqual(participant.id, '4');
                assert.strictEqual(participant.privKeyList.length, 0);
            });
        });

        describe('#_setKeys() method', function() {
            it('update local key state', function() {
                var numMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.privKeyList = [_PRIV_KEY_B()];
                var intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    participant.members.push(i.toString());
                    intKeys.push(_PRIV_KEY());
                }
                participant._setKeys(intKeys);
                assert.deepEqual(participant.intKeys, intKeys);
                assert.notStrictEqual(participant.groupKey, _td.C25519_PRIV_KEY_B);
            });

            it('update local key state with key list', function() {
                var numMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.privKeyList = [_PRIV_KEY_B(), _PRIV_KEY_B()];
                var intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    participant.members.push(i.toString());
                    intKeys.push(_PRIV_KEY());
                }
                participant._setKeys(intKeys);
                assert.deepEqual(participant.intKeys, intKeys);
                assert.notStrictEqual(participant.groupKey, _td.C25519_PRIV_KEY_B);
            });
        });

        describe('#_renewPrivKey() method', function() {
            it('renewing private key and int keys', function() {
                var numMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.privKeyList = [_PRIV_KEY_B()];
                participant.intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                }
                var cardinalKey = participant._renewPrivKey();
                assert.lengthOf(participant.privKeyList, 2);
                assert.strictEqual(utils.bytes2string(participant.privKeyList[0]), _td.C25519_PRIV_KEY);
                assert.notDeepEqual(cardinalKey, _td.C25519_PRIV_KEY_B);
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

        describe('#upflow() method', function() {
            it('ika upflow, no previous messages', function() {
                var participant = new ns.CliquesMember('1');
                var members = ['1', '2', '3', '4', '5', '6'];
                var startMessage = new ns.CliquesMessage();
                startMessage.members = members;
                startMessage.agreement = 'ika';
                startMessage.flow = 'up';
                var newMessage = participant.upflow(startMessage);
                assert.deepEqual(participant.members, members);
                assert.deepEqual(newMessage.members, members);
                assert.lengthOf(participant.privKeyList, 1);
                assert.strictEqual(_tu.keyBits(participant.privKeyList[0], 8), 256);
                assert.strictEqual(newMessage.agreement, 'ika');
                assert.strictEqual(newMessage.flow, 'up');
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
                message.flow = 'up';
                for (var i = 0; i < numMembers - 1; i++) {
                    message = participants[i].upflow(message);
                    assert.deepEqual(participants[i].members, members);
                    assert.lengthOf(participants[i].privKeyList, 1);
                    assert.strictEqual(_tu.keyBits(participants[i].privKeyList[0], 8), 256);
                    assert.strictEqual(message.agreement, 'ika');
                    assert.strictEqual(message.flow, 'up');
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
                assert.lengthOf(participants[i].privKeyList, 1);
                assert.strictEqual(_tu.keyBits(participants[i].privKeyList[0], 8), 256);
                assert.strictEqual(message.agreement, 'ika');
                assert.strictEqual(message.flow, 'down');
                assert.lengthOf(message.intKeys, numMembers);
                assert.strictEqual(_tu.keyBits(message.intKeys[0], 8), 256);
                assert.strictEqual(_tu.keyBits(message.intKeys[numMembers - 1], 8), 256);
                // Last one goes to all.
                assert.strictEqual(message.source, members[numMembers - 1]);
                assert.strictEqual(message.dest, '');
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
                participant.privKeyList = [_PRIV_KEY_B()];
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'down';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
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
                participant.privKeyList = [_PRIV_KEY_B()];
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'down';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
                participant.downflow(broadcastMessage);
                assert.strictEqual(participant.intKeys, messageKeys);
                assert.strictEqual(_tu.keyBits(participant.groupKey, 8), 256);
                assert.notStrictEqual(participant.groupKey, _td.C25519_PRIV_KEY_B);
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
                participant.privKeyList = [_PRIV_KEY_B()];
                var broadcastMessage = new ns.CliquesMessage();
                broadcastMessage.source = '5';
                broadcastMessage.agreement = 'ika';
                broadcastMessage.flow = 'down';
                broadcastMessage.members = members;
                broadcastMessage.intKeys = messageKeys;
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
                assert.throws(function() { participant.akaJoin([]); },
                              'No members to add.');
            });

            it('join duplicate member list using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                assert.throws(function() { participant.akaJoin(['2']); },
                              'Duplicates in member list detected!');
            });

            it('join a member using aka', function() {
                var numMembers = 5;
                var members = [];
                var participant = new ns.CliquesMember('3');
                participant.privKeyList = [_PRIV_KEY_B()];
                participant.groupKey = _PRIV_KEY();
                participant.intKeys = [];
                for (var i = 1; i <= numMembers; i++) {
                    members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant.members.push(i.toString());
                }
                var message = participant.akaJoin(['6']);
                assert.lengthOf(message.members, 6);
                assert.lengthOf(message.intKeys, 6);
                assert.strictEqual(_tu.keyBits(participant.privKeyList[1], 8), 256);
                assert.deepEqual(participant.privKeyList[0], _td.C25519_PRIV_KEY_B);
                assert.notDeepEqual(participant.privKeyList[1], _td.C25519_PRIV_KEY_B);
                assert.strictEqual(message.agreement, 'aka');
                assert.strictEqual(message.flow, 'up');
                assert.strictEqual(_tu.keyBits(message.intKeys[0], 8), 256);
                assert.strictEqual(_tu.keyBits(message.intKeys[5], 8), 256);
                assert.strictEqual(message.source, '3');
                assert.strictEqual(message.dest, '6');
                // Upflow for the new guy '6'.
                var newParticipant = new ns.CliquesMember('6');
                message = newParticipant.upflow(message);
                // Downflow for initiator and new guy.
                participant.downflow(message);
                newParticipant.downflow(message);
                assert.deepEqual(participant.groupKey, newParticipant.groupKey);
            });
        });

        describe('#akaExclude() method', function() {
            it('exclude empty member list using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                assert.throws(function() { participant.akaExclude([]); },
                              'No members to exclude.');
            });

            it('exclude non existing member using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                assert.throws(function() { participant.akaExclude(['1', '7']); },
                              'Members list to exclude is not a sub-set of previous members!');
            });

            it('exclude self using aka', function() {
                var members = ['1', '2', '3', '4', '5'];
                var participant = new ns.CliquesMember('3');
                participant.members = members;
                assert.throws(function() { participant.akaExclude(['3', '5']); },
                              'Cannot exclude mysefl.');
            });

            it('exclude members using aka', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant.privKeyList = [_PRIV_KEY_B()];
                    participant.groupKey = _PRIV_KEY();
                }
                sinon_sandbox.spy(ns, 'deriveGroupKey');
                // Exclude members '1' and '4'.
                var thenMembers = ['2', '3', '5'];
                var message = participant.akaExclude(['1', '4']);
                assert.deepEqual(message.members, thenMembers);
                assert.deepEqual(participant.members, thenMembers);
                assert.deepEqual(participant.privKeyList[0], _td.C25519_PRIV_KEY_B);
                assert.notDeepEqual(participant.privKeyList[1], _td.C25519_PRIV_KEY_B);
                assert.notDeepEqual(participant.groupKey, _td.C25519_PRIV_KEY_B);
                assert.notDeepEqual(participant.groupKey, undefined);
                sinon_assert.calledOnce(ns.deriveGroupKey);
            });
        });

        describe('#akaRefresh() method', function() {
            it('refresh own private key using aka', function() {
                var initialMembers = 5;
                var participant = new ns.CliquesMember('3');
                participant.intKeys = [];
                participant.privKeyList = [_PRIV_KEY_B()];
                participant.groupKey = _PRIV_KEY();
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                }
                var chkGroupKey = participant.groupKey;
                var message = participant.akaRefresh();
                assert.strictEqual(utils.bytes2string(participant.privKeyList[0]), _td.C25519_PRIV_KEY);
                assert.notStrictEqual(participant.privKeyList[1], _td.C25519_PRIV_KEY_B);
                assert.notStrictEqual(participant.groupKey, chkGroupKey);
                assert.lengthOf(participant.privKeyList, 2);
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
                for (var i = 1; i <= initialMembers; i++) {
                    participant.members.push(i.toString());
                    participant.intKeys.push(_PRIV_KEY());
                    participant.privKeyList = [_PRIV_KEY_B()];
                    participant.groupKey = _PRIV_KEY();
                }
                participant.akaQuit();
                assert.deepEqual(participant.members, ['1', '2', '4', '5']);
                assert.deepEqual(participant.intKeys, []);
                assert.deepEqual(participant.privKeyList, []);
            });
        });

        describe('whole ika', function() {
            it('whole flow for 5 ika members, 2 joining, 2 others leaving, refresh', function() {
                this.timeout(this.timeout() * 5);
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
                while (message.flow === 'up') {
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
                while (message.flow === 'up') {
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
            });
        });
    });

    /**
     * Returns a fresh copy of the private key constant, protected from "cleaning".
     * @returns Array of words.
     */
    function _PRIV_KEY_B() {
        return utils.clone(_td.C25519_PRIV_KEY_B);
    }

    function _PRIV_KEY() {
        return utils.clone(_td.C25519_PRIV_KEY);
    }
});
