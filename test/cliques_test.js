/**
 * @module cliques_test
 * 
 * Test of cliques module.
 */
"use strict";

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
            expect(_scalarMultiplyDebug('1')).toBe('1*G');
            expect(_scalarMultiplyDebug('2')).toBe('2*G');
        });
        
        it('should multiply debug priv key with intermediate key', function() {
            expect(_scalarMultiplyDebug('1', '2*G')).toBe('1*2*G');
            expect(_scalarMultiplyDebug('2', '3*4*5*G')).toBe('2*3*4*5*G');
        });
    });

    describe('_scalarMultiply()', function() {
        it('should multiply with base point if no key given', function() {
            var compPubKey = _scalarMultiply(PRIV_KEY);
            expect(arrayCompare(compPubKey, PUB_KEY)).toBe(true);
        });
        
        it('should multiply priv key with intermediate key', function() {
            var compPubKey = _scalarMultiply(PRIV_KEY, PRIV_KEY);
            expect(arrayCompare(compPubKey, COMP_KEY)).toBe(true);
        });
    });
});

describe('CliquesMember class', function() {
    describe('constructor', function() {
        it('simple CliquesMember constructor', function() {
            var participant = new CliquesMember('4');
            expect(participant.id).toBe('4');
        });
    });

    describe('startIka() method', function() {
        it('start the IKA', function() {
            var participant = new CliquesMember('1');
            spyOn(participant, 'ikaUpflow');
            var others = ['2', '3', '4', '5', '6'];
            participant.startIka(others);
            expect(participant.ikaUpflow).toHaveBeenCalled();
        });
    });

    describe('ikaUpflow() method', function() {
        it('ika upflow, no previous messages', function() {
            var participant = new CliquesMember('1');
            var members = ['1', '2', '3', '4', '5', '6'];
            var startMessage = new CliquesMessage();
            startMessage.members = members;
            var newMessage = participant.ikaUpflow(startMessage);
            expect(participant.members).toBe(members);
            expect(newMessage.members).toBe(members);
            expect(keyBits(participant.privKey)).toBe(256);
            expect(newMessage.msgType).toBe('ika_upflow');
            expect(newMessage.keys.length).toBe(2);
            expect(newMessage.keys[0]).toBe(null);
            expect(keyBits(newMessage.keys[newMessage.keys.length - 1])).toBe(256);
            expect(newMessage.source).toBe('1');
            expect(newMessage.dest).toBe('2');
        });
        
        it('ika upflow, , multiple calls', function() {
            var numMembers = 5;
            var members = [];
            var participants = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                participants.push(new CliquesMember(i.toString()));
            }
            var message = new CliquesMessage();
            message.members = members;
            for (var i = 0; i < numMembers - 1; i++) {
                message = participants[i].ikaUpflow(message);
                expect(arrayCompare(participants[i].members, members)).toBe(true);
                expect(keyBits(participants[i].privKey)).toBe(256);
                expect(message.msgType).toBe('ika_upflow');
                expect(message.keys.length).toBe(i + 2);
                expect(keyBits(message.keys[i + 1])).toBe(256);
                if (i === 0) {
                    expect(message.keys[0]).toBe(null);
                } else {
                    expect(keyBits(message.keys[0])).toBe(256);
                }
                expect(message.source).toBe(members[i]);
                expect(message.dest).toBe(members[i + 1]);
            }

            // The last member behaves differently.
            message = participants[numMembers - 1].ikaUpflow(message);
            expect(arrayCompare(participants[i].members, members)).toBe(true);
            expect(keyBits(participants[i].privKey)).toBe(256);
            expect(message.msgType).toBe('ika_downflow');
            expect(message.keys.length).toBe(numMembers);
            expect(keyBits(message.keys[0])).toBe(256);
            expect(keyBits(message.keys[numMembers - 1])).toBe(256);
            // Last one goes to all.
            expect(message.source).toBe(members[numMembers - 1]);
            expect(message.dest).toBe('');
        });
    });
    
    describe('ikaDownflow() method', function() {
        it('ika downflow message process', function() {
            var numMembers = 5;
            var members = [];
            var messageKeys = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                messageKeys.push(PRIV_KEY);
            }
            var participant = new CliquesMember('3');
            participant.members = members;
            participant.privKey = PRIV_KEY;
            var broadcastMessage = new CliquesMessage();
            broadcastMessage.source = '5';
            broadcastMessage.msgType = 'ika_downflow';
            broadcastMessage.members = members;
            broadcastMessage.keys = messageKeys;
            broadcastMessage.debugKeys = members.map(_arrayCopy);
            participant.ikaDownflow(broadcastMessage);
            expect(arrayCompare(participant.intKeys, messageKeys)).toBe(true);
            expect(keyBits(participant.groupKey)).toBe(256);
            expect(arrayCompare(participant.groupKey, PRIV_KEY)).toBe(false);
        });
        
        it('ika downflow member list mismatch', function() {
            var numMembers = 5;
            var members = [];
            var messageKeys = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                messageKeys.push(PRIV_KEY);
            }
            var participant = new CliquesMember('3');
            participant.members = members;
            participant.privKey = PRIV_KEY;
            var broadcastMessage = new CliquesMessage();
            broadcastMessage.source = '5';
            broadcastMessage.msgType = 'ika_downflow';
            broadcastMessage.members = ['0'].concat(members);
            broadcastMessage.keys = messageKeys;
            broadcastMessage.debugKeys = members.map(_arrayCopy);
            expect(function() { participant.ikaDownflow(broadcastMessage); })
                .toThrow('Member list mis-match in protocol');
        });
    });
    
    describe('whole ika', function() {
        it('whole ika flow for 5 members', function() {
            var numMembers = 5;
            var initiator = 0;
            var members = [];
            var participants = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                participants.push(new CliquesMember(i.toString()));
            }
            var otherMembers = [];
            for (var i = 2; i <= numMembers; i++) {
                otherMembers.push(i.toString());
            }
            // Start me up.
            var message = participants[initiator].startIka(otherMembers);
            while (message.msgType === 'ika_upflow') {
                var nextRecipient = message.dest;
                if (message.dest !== '') {
                    message = participants[nextRecipient - 1].ikaUpflow(message);
                } else {
                    throw new Error("This shouldn't happen!");
                }
            }
            var keyCheck = null;
            for (var i = 0; i < numMembers; i++) {
                var participant = participants[i];
                var member = members[i];
                participant.ikaDownflow(message);
                expect(participant.id).toBe(member);
                expect(arrayCompare(participant.members, members)).toBe(true);
                if (!keyCheck) {
                    keyCheck = participant.groupKey;
                } else {
                    expect(arrayCompare(participant.groupKey, keyCheck)).toBe(true);
                }
            }
        });
    });
});


