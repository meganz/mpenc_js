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
            expect(_arrayIsSubSet(subset, superset));
            assert.strictEqual(_arrayIsSubSet(superset, subset), false);
        });
    });
    
    describe('_arrayIsSet()', function() {
        it('check for non-duplicatoin of members in array', function() {
            var theArray = ['1', '2', '3'];
            expect(_arrayIsSet(theArray));
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

    describe('#ika() method', function() {
        it('start the IKA', function() {
            var participant = new CliquesMember('1');
            var spy = sinon.spy();
            participant.upflow = spy;
            var others = ['2', '3', '4', '5', '6'];
            participant.ika(others);
            sinon.assert.calledOnce(spy);
        });
    });

    describe('#upflow() method', function() {
//        it('ika upflow, no previous messages', function() {
//            var participant = new CliquesMember('1');
//            var members = ['1', '2', '3', '4', '5', '6'];
//            var startMessage = new CliquesMessage();
//            startMessage.members = members;
//            var newMessage = participant.upflow(startMessage);
//            expect(participant.members, members);
//            expect(newMessage.members, members);
//            expect(_utils.keyBits(participant.privKey), 256);
//            expect(newMessage.agreement, 'ika');
//            expect(newMessage.flow, 'upflow');
//            expect(newMessage.keys.length, 2);
//            expect(newMessage.keys[0], null);
//            expect(keyBits(newMessage.keys[newMessage.keys.length - 1]), 256);
//            expect(newMessage.source, '1');
//            expect(newMessage.dest, '2');
//        });
        
//        it('ika upflow duplicates in member list', function() {
//            var participant = new CliquesMember('1');
//            var members = ['3', '1', '2', '3', '4', '5', '6'];
//            var startMessage = new CliquesMessage();
//            startMessage.members = members;
//            expect(function() { participant.ikaUpflow(startMessage); })
//                .toThrow('Duplicates in member list detected!');
//        });
//        
//        it('ika upflow, multiple calls', function() {
//            var numMembers = 5;
//            var members = [];
//            var participants = [];
//            for (var i = 1; i <= numMembers; i++) {
//                members.push(i.toString());
//                participants.push(new CliquesMember(i.toString()));
//            }
//            var message = new CliquesMessage();
//            message.members = members;
//            for (var i = 0; i < numMembers - 1; i++) {
//                message = participants[i].ikaUpflow(message);
//                expect(arrayCompare(participants[i].members, members), true);
//                expect(keyBits(participants[i].privKey), 256);
//                expect(message.msgType, 'ika_upflow');
//                expect(message.keys.length, i + 2);
//                expect(keyBits(message.keys[i + 1]), 256);
//                if (i === 0) {
//                    expect(message.keys[0], null);
//                } else {
//                    expect(keyBits(message.keys[0]), 256);
//                }
//                expect(message.source, members[i]);
//                expect(message.dest, members[i + 1]);
//            }
//
//            // The last member behaves differently.
//            message = participants[numMembers - 1].ikaUpflow(message);
//            expect(arrayCompare(participants[i].members, members), true);
//            expect(keyBits(participants[i].privKey), 256);
//            expect(message.msgType, 'ika_downflow');
//            expect(message.keys.length, numMembers);
//            expect(keyBits(message.keys[0]), 256);
//            expect(keyBits(message.keys[numMembers - 1]), 256);
//            // Last one goes to all.
//            expect(message.source, members[numMembers - 1]);
//            expect(message.dest, '');
//        });
    });
    
//    describe('#ikaDownflow() method', function() {
//        it('ika downflow message process', function() {
//            var numMembers = 5;
//            var members = [];
//            var messageKeys = [];
//            for (var i = 1; i <= numMembers; i++) {
//                members.push(i.toString());
//                messageKeys.push(PRIV_KEY);
//            }
//            var participant = new CliquesMember('3');
//            participant.members = members;
//            participant.privKey = PRIV_KEY;
//            var broadcastMessage = new CliquesMessage();
//            broadcastMessage.source = '5';
//            broadcastMessage.msgType = 'ika_downflow';
//            broadcastMessage.members = members;
//            broadcastMessage.keys = messageKeys;
//            broadcastMessage.debugKeys = members.map(_arrayCopy);
//            participant.ikaDownflow(broadcastMessage);
//            expect(arrayCompare(participant.intKeys, messageKeys), true);
//            expect(keyBits(participant.groupKey), 256);
//            expect(arrayCompare(participant.groupKey, PRIV_KEY), false);
//        });
//        
//        it('ika downflow duplicates in member list', function() {
//            var numMembers = 5;
//            var members = [];
//            var messageKeys = [];
//            for (var i = 1; i <= numMembers; i++) {
//                members.push(i.toString());
//                messageKeys.push(PRIV_KEY);
//            }
//            members.push('1');
//            messageKeys.push(PRIV_KEY);
//            var participant = new CliquesMember('3');
//            participant.members = members;
//            participant.privKey = PRIV_KEY;
//            var broadcastMessage = new CliquesMessage();
//            broadcastMessage.source = '5';
//            broadcastMessage.msgType = 'ika_downflow';
//            broadcastMessage.members = ['0'].concat(members);
//            broadcastMessage.keys = messageKeys;
//            broadcastMessage.debugKeys = members.map(_arrayCopy);
//            expect(function() { participant.ikaDownflow(broadcastMessage); })
//                .toThrow('Duplicates in member list detected!');
//        });
//        
//        it('ika downflow member list mismatch', function() {
//            var numMembers = 5;
//            var members = [];
//            var messageKeys = [];
//            for (var i = 1; i <= numMembers; i++) {
//                members.push(i.toString());
//                messageKeys.push(PRIV_KEY);
//            }
//            var participant = new CliquesMember('3');
//            participant.members = members;
//            participant.privKey = PRIV_KEY;
//            var broadcastMessage = new CliquesMessage();
//            broadcastMessage.source = '5';
//            broadcastMessage.msgType = 'ika_downflow';
//            broadcastMessage.members = ['0'].concat(members);
//            broadcastMessage.keys = messageKeys;
//            broadcastMessage.debugKeys = members.map(_arrayCopy);
//            expect(function() { participant.ikaDownflow(broadcastMessage); })
//                .toThrow('Member list mis-match in protocol');
//        });
//    });
//    
//    describe('whole ika', function() {
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
//                    message = participants[nextRecipient - 1].ikaUpflow(message);
//                } else {
//                    throw new Error("This shouldn't happen!");
//                }
//            }
//            var keyCheck = null;
//            for (var i = 0; i < numMembers; i++) {
//                var participant = participants[i];
//                var member = members[i];
//                participant.ikaDownflow(message);
//                expect(participant.id, member);
//                expect(arrayCompare(participant.members, members), true);
//                if (!keyCheck) {
//                    keyCheck = participant.groupKey;
//                } else {
//                    expect(arrayCompare(participant.groupKey, keyCheck), true);
//                }
//            }
//        });
//    });
});


