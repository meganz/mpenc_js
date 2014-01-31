/**
 * @module cliques_test
 * 
 * Test of cliques module.
 */
"use strict";

var assert = chai.assert;

// 0x6e3b0789a77feb8dd878278b1233a8c06070506c7c93f6de8894bbeac1db06dd
var PRIV_KEY_B32 = '3r3a6e2o77lrxmhqj4lciz2rqdaobigy7et63pirff35la5wbw5';
var PRIV_KEY = c255lbase32decode(PRIV_KEY_B32);
// 0x6a998a38c3f189ed5b646360512a13957c4d87df93ed34b33b5f187ea151094d
var PUB_KEY_B32  = '2uzri4mh4mj5vnwiy3akevbhfl4jwd57e7ngsztwxyyp2qvcckn';
var PUB_KEY = c255lbase32decode(PUB_KEY_B32);
// 0x365c1e572ab6d6e9eeb9fe709e90207d9b2dca53203b6408ee2dae6c6fef6e28
var COMP_KEY_B32 = 'ns4dzlsvnww5hxlt7tqt2ica7m3fxffgib3mqeo4lnonrx663ri';
var COMP_KEY = c255lbase32decode(COMP_KEY_B32);

describe("module level", function() {
    describe('_scalarMultiplyDebug()', function() {
        it('should multiply debug with base point if no key given', function() {
            assert.strictEqual(_scalarMultiplyDebug('1'), '1*G');
            assert.strictEqual(_scalarMultiplyDebug('2'), '2*G');
        });
        
        it('should multiply debug priv key with intermediate key', function() {
            assert.deepEqual(_scalarMultiplyDebug('1', '2*G'), '1*2*G');
            assert.deepEqual(_scalarMultiplyDebug('2', '3*4*5*G'), '2*3*4*5*G');
        });
    });

    describe('_scalarMultiply()', function() {
        it('should multiply with base point if no key given', function() {
            var compPubKey = _scalarMultiply(PRIV_KEY);
            assert.deepEqual(compPubKey, PUB_KEY);
        });
        
        it('should multiply priv key with intermediate key', function() {
            var compPubKey = _scalarMultiply(PRIV_KEY, PRIV_KEY);
            assert.deepEqual(compPubKey, COMP_KEY);
        });
    });
    
    describe('_arrayIsSubSet()', function() {
        it('check for sub/superset between arrays', function() {
            var subset = ['1', '2', '3'];
            var superset = ['0', '1', '2', '3', '4'];
            assert.ok(_arrayIsSubSet(subset, superset));
            assert.strictEqual(_arrayIsSubSet(superset, subset), false);
        });
    });
    
    describe('_arrayIsSet()', function() {
        it('check for non-duplicatoin of members in array', function() {
            var theArray = ['1', '2', '3'];
            assert.ok(_arrayIsSet(theArray));
            assert.strictEqual(_arrayIsSet(['2'].concat(theArray)), false);
        });
    });
});

describe('CliquesMember class', function() {
    describe('constructor', function() {
        it('simple CliquesMember constructor', function() {
            var participant = new CliquesMember('4');
            assert.strictEqual(participant.id, '4');
        });
    });

    describe('#_setKeys() method', function() {
        it('update local key state', function() {
            var numMembers = 5;
            var participant = new CliquesMember('3');
            participant.privKey = _PRIV_KEY();
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
            assert.notStrictEqual(participant.groupKey, PRIV_KEY);
            assert.strictEqual(participant._debugGroupKey, '3*1*2*4*5*G');
        });
    });

    describe('#_renewPrivKey() method', function() {
        it('reniewing private key and int keys', function() {
            var numMembers = 5;
            var participant = new CliquesMember('3');
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
            assert.notStrictEqual(participant.privKey, PRIV_KEY);
            assert.strictEqual(participant._debugPrivKey, "3'");
            assert.notDeepEqual(response.cardinalKey, PRIV_KEY);
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
            var participant = new CliquesMember('1');
            var spy = sinon.spy();
            participant.upflow = spy;
            var otherMembers = ['2', '3', '4', '5', '6'];
            participant.ika(otherMembers);
            sinon.assert.calledOnce(spy);
        });
    
        it('start the IKA without members', function() {
            var participant = new CliquesMember('1');
            assert.throws(function() { participant.ika([]); },
                          'No members to add.');
        });
    });

    describe('#upflow() method', function() {
        it('ika upflow, no previous messages', function() {
            var participant = new CliquesMember('1');
            var members = ['1', '2', '3', '4', '5', '6'];
            var startMessage = new CliquesMessage();
            startMessage.members = members;
            startMessage.agreement = 'ika';
            startMessage.flow = 'upflow';
            var newMessage = participant.upflow(startMessage);
            assert.deepEqual(participant.members, members);
            assert.deepEqual(newMessage.members, members);
            assert.strictEqual(keyBits(participant.privKey), 256);
            assert.strictEqual(newMessage.agreement, 'ika');
            assert.strictEqual(newMessage.flow, 'upflow');
            assert.lengthOf(newMessage.keys, 2);
            assert.strictEqual(newMessage.keys[0], null);
            assert.strictEqual(keyBits(newMessage.keys[newMessage.keys.length - 1]), 256);
            assert.strictEqual(newMessage.source, '1');
            assert.strictEqual(newMessage.dest, '2');
        });
        
        it('ika upflow duplicates in member list', function() {
            var participant = new CliquesMember('1');
            var members = ['3', '1', '2', '3', '4', '5', '6'];
            var startMessage = new CliquesMessage();
            startMessage.members = members;
            assert.throws(function() { participant.upflow(startMessage); },
                          'Duplicates in member list detected!');
        });
        
        it('ika upflow, multiple calls', function() {
            var numMembers = 5;
            var members = [];
            var participants = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                participants.push(new CliquesMember(i.toString()));
            }
            var message = new CliquesMessage();
            message.members = members;
            message.agreement = 'ika';
            message.flow = 'upflow';
            for (var i = 0; i < numMembers - 1; i++) {
                message = participants[i].upflow(message);
                assert.deepEqual(participants[i].members, members);
                assert.strictEqual(keyBits(participants[i].privKey), 256);
                assert.strictEqual(message.agreement, 'ika');
                assert.strictEqual(message.flow, 'upflow');
                assert.lengthOf(message.keys, i + 2);
                assert.strictEqual(keyBits(message.keys[i + 1]), 256);
                if (i === 0) {
                    assert.strictEqual(message.keys[0], null);
                } else {
                    assert.strictEqual(keyBits(message.keys[0]), 256);
                }
                assert.strictEqual(message.source, members[i]);
                assert.strictEqual(message.dest, members[i + 1]);
            }

            // The last member behaves differently.
            message = participants[numMembers - 1].upflow(message);
            assert.deepEqual(participants[i].members, members);
            assert.strictEqual(keyBits(participants[i].privKey), 256);
            assert.strictEqual(message.agreement, 'ika');
            assert.strictEqual(message.flow, 'downflow');
            assert.lengthOf(message.keys, numMembers);
            assert.strictEqual(keyBits(message.keys[0]), 256);
            assert.strictEqual(keyBits(message.keys[numMembers - 1]), 256);
            // Last one goes to all.
            assert.strictEqual(message.source, members[numMembers - 1]);
            assert.strictEqual(message.dest, '');
        });
    });
    
    describe('#downflow() method', function() {
        it('ika downflow duplicates in member list', function() {
            var members = ['3', '1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = ['1', '2', '3', '4', '5'];
            var broadcastMessage = new CliquesMessage();
            broadcastMessage.members = members;
            assert.throws(function() { participant.downflow(broadcastMessage); },
                          'Duplicates in member list detected!');
        });
        
        it('ika downflow member list mismatch', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = ['1', '2', '3', '4'];
            var broadcastMessage = new CliquesMessage();
            broadcastMessage.members = members;
            broadcastMessage.agreement = 'ika';
            assert.throws(function() { participant.downflow(broadcastMessage); },
                          'Member list mis-match in protocol');
        });
    
        it('ika downflow message process', function() {
            var numMembers = 5;
            var members = [];
            var messageKeys = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                messageKeys.push(_PRIV_KEY());
            }
            var participant = new CliquesMember('3');
            participant.members = members;
            participant.privKey = _PRIV_KEY();
            var broadcastMessage = new CliquesMessage();
            broadcastMessage.source = '5';
            broadcastMessage.agreement = 'ika';
            broadcastMessage.flow = 'downflow';
            broadcastMessage.members = members;
            broadcastMessage.keys = messageKeys;
            broadcastMessage.debugKeys = members.map(_arrayCopy);
            participant.downflow(broadcastMessage);
            assert.deepEqual(participant.intKeys, messageKeys);
            assert.strictEqual(keyBits(participant.groupKey), 256);
            assert.notDeepEqual(participant.groupKey, PRIV_KEY);
        });
    });

    describe('#akaJoin() method', function() {
        it('join empty member list using aka', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = members;
            participant._debugGroupKey = '1*2*3*4*5*G';
            assert.throws(function() { participant.akaJoin([]); },
                          'No members to add.');
        });
        
        it('join duplicate member list using aka', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = members;
            participant._debugGroupKey = '1*2*3*4*5*G';
            assert.throws(function() { participant.akaJoin(['2']); },
                          'Duplicates in member list detected!');
        });
    });

    describe('#akaExclude() method', function() {
        it('exclude empty member list using aka', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = members;
            participant._debugGroupKey = '1*2*3*4*5*G';
            assert.throws(function() { participant.akaExclude([]); },
                          'No members to exclude.');
        });
        
        it('exclude non existing member using aka', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = members;
            participant._debugGroupKey = '1*2*3*4*5*G';
            assert.throws(function() { participant.akaExclude(['1', '7']); },
                          'Members list to exclude is not a sub-set of previous members!');
        });
        
        it('exclude self using aka', function() {
            var members = ['1', '2', '3', '4', '5'];
            var participant = new CliquesMember('3');
            participant.members = members;
            participant._debugGroupKey = '1*2*3*4*5*G';
            assert.throws(function() { participant.akaExclude(['3', '5']); },
                          'Cannot exclude mysefl.');
        });


    });
    
    describe('whole ika', function() {
//        it('whole ika flow for 5 members', function() {
//            var numMembers = 5;
//            var initiator = 0;
//            var members = [];
//            var participants = [];
//            for (var i = 1; i <= numMembers; i++) {
//                members.push(i.toString());
//                participants.push(new CliquesMember(i.toString()));
//            }
//            var otherMembers = [];
//            for (var i = 2; i <= numMembers; i++) {
//                otherMembers.push(i.toString());
//            }
//            // Start me up.
//            var message = participants[initiator].startIka(otherMembers);
//            while (message.msgType === 'ika_upflow') {
//                var nextRecipient = message.dest;
//                if (message.dest !== '') {
//                    message = participants[nextRecipient - 1].upflow(message);
//                } else {
//                    throw new Error("This shouldn't happen!");
//                }
//            }
//            var keyCheck = null;
//            for (var i = 0; i < numMembers; i++) {
//                var participant = participants[i];
//                var member = members[i];
//                participant.ikaDownflow(message);
//                assert(participant.id, member);
//                assert(arrayCompare(participant.members, members), true);
//                if (!keyCheck) {
//                    keyCheck = participant.groupKey;
//                } else {
//                    assert(arrayCompare(participant.groupKey, keyCheck), true);
//                }
//            }
//        });
    });
});


/**
 * Returns a fresh copy of the private key constant, protected from "cleaning".
 * @returns Array of words.
 */
function _PRIV_KEY() {
    return PRIV_KEY.map(_arrayCopy);
}
