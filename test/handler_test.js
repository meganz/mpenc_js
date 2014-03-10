/**
 * @fileOverview
 * Test of the `mpenc.handler` module.
 */

/*
 * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

"use strict";

var assert = chai.assert;

describe("ProtocolHandler class", function() {
    var ns = mpenc.handler;
    
    describe('constructor', function() {
        it('fails for missing params', function() {
            assert.throws(function() { new ns.ProtocolHandler('42', _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY); },
                          "Constructor call missing required parameters.");
        });
        
        it('just make an instance', function() {
            var handler = new ns.ProtocolHandler('42',
                                                 _td.RSA_PRIV_KEY,
                                                 _td.RSA_PUB_KEY,
                                                 _td.STATIC_PUB_KEY_DIR);
            assert.strictEqual(handler.id, '42');
            assert.ok(handler.staticPubKeyDir.get('3'));
            assert.deepEqual(handler.askeMember.staticPrivKey, _td.RSA_PRIV_KEY);
            assert.ok(handler.askeMember.staticPubKeyDir);
            assert.ok(handler.cliquesMember);
        });
    });
    
    describe('#_mergeMessages() method', function() {
        it('fail for mismatching senders', function() {
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var cliquesMessage = {source: '1', dest: '2', agreement: 'ika', flow: 'upflow',
                                  members: ['1', '2', '3', '4', '5', '6'], intKeys: null};
            var askeMessage = {source: '2', dest: '2', flow: 'upflow',
                               members: ['1', '2', '3', '4', '5', '6'],
                               nonces: null, pubKeys: null, sessionSignature: null};
            assert.throws(function() { participant._mergeMessages(cliquesMessage, askeMessage); },
                          "Message source mismatch, this shouldn't happen.");
        });
        
        it('fail for mismatching receivers', function() {
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var cliquesMessage = {source: '1', dest: '2', agreement: 'ika', flow: 'upflow',
                                  members: ['1', '2', '3', '4', '5', '6'], intKeys: null};
            var askeMessage = {source: '1', dest: '', flow: 'upflow',
                               members: ['1', '2', '3', '4', '5', '6'],
                               nonces: null, pubKeys: null, sessionSignature: null};
            assert.throws(function() { participant._mergeMessages(cliquesMessage, askeMessage); },
                          "Message destination mismatch, this shouldn't happen.");
        });
        
        it('just merge the messages', function() {
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var cliquesMessage = {source: '1', dest: '2', agreement: 'ika', flow: 'upflow',
                                  members: ['1', '2', '3', '4', '5', '6'], intKeys: null};
            var askeMessage = {source: '1', dest: '2', flow: 'upflow',
                               members: ['1', '2', '3', '4', '5', '6'],
                               nonces: null, pubKeys: null, sessionSignature: null};
            var message = participant._mergeMessages(cliquesMessage, askeMessage);
            assert.strictEqual(message.source, cliquesMessage.source);
            assert.strictEqual(message.dest, cliquesMessage.dest);
            assert.strictEqual(message.flow, cliquesMessage.flow);
            assert.strictEqual(message.agreement, 'initial');
            assert.deepEqual(message.members, cliquesMessage.members);
            assert.deepEqual(message.intKeys, cliquesMessage.intKeys);
            assert.deepEqual(message.nonces, askeMessage.nonces);
            assert.deepEqual(message.pubKeys, askeMessage.pubKeys);
            assert.strictEqual(message.sessionSignature, askeMessage.sessionSignature);
        });
    });
    
    describe('#_getCliquesMessage() method', function() {
        it('the vanilla ika case', function() {
            var message = {
                source: '1',
                dest: '2',
                agreement: 'initial',
                flow: 'upflow',
                members: ['1', '2', '3', '4', '5', '6'],
                intKeys: null,
                nonces: null,
                pubKeys: null,
                sessionSignature: null
            };
            
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var compare = {source: '1', dest: '2', agreement: 'ika', flow: 'upflow',
                           members: ['1', '2', '3', '4', '5', '6'], intKeys: null};
            var cliquesMessage = participant._getCliquesMessage(message);
            assert.strictEqual(cliquesMessage.source, compare.source);
            assert.strictEqual(cliquesMessage.dest, compare.dest);
            assert.strictEqual(cliquesMessage.flow, compare.flow);
            assert.strictEqual(cliquesMessage.agreement, compare.agreement);
            assert.deepEqual(cliquesMessage.members, compare.members);
            assert.deepEqual(cliquesMessage.intKeys, compare.intKeys);
        });
    });
    
    describe('#_getAskeMessage() method', function() {
        it('the vanilla ika case', function() {
            var message = {
                source: '1',
                dest: '2',
                agreement: 'initial',
                flow: 'upflow',
                members: ['1', '2', '3', '4', '5', '6'],
                intKeys: null,
                nonces: null,
                pubKeys: null,
                sessionSignature: null
            };
            
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var compare = {source: '1', dest: '2', flow: 'upflow',
                           members: ['1', '2', '3', '4', '5', '6'],
                           nonces: null, pubKeys: null, sessionSignature: null};
            var askeMessage = participant._getAskeMessage(message);
            assert.strictEqual(askeMessage.source, compare.source);
            assert.strictEqual(askeMessage.dest, compare.dest);
            assert.strictEqual(askeMessage.flow, compare.flow);
            assert.deepEqual(askeMessage.members, compare.members);
            assert.deepEqual(askeMessage.nonces, compare.nonces);
            assert.deepEqual(askeMessage.pubKeys, compare.pubKeys);
            assert.deepEqual(askeMessage.sessionSignature, compare.sessionSignature);
        });
    });
    
    // TODO:
    // * protocol state machine
    // * protocol codec
    
    describe('#start() method', function() {
        it('start/initiate a group session', function() {
            var participant = new ns.ProtocolHandler('1',
                                                     _td.RSA_PRIV_KEY,
                                                     _td.RSA_PUB_KEY,
                                                     _td.STATIC_PUB_KEY_DIR);
            var cliquesSpy = sinon.spy();
            var askeSpy = sinon.spy();
            var mergeMessagesStub = sinon.stub().returns(null);
            participant.cliquesMember.ika = cliquesSpy;
            participant.askeMember.commit = askeSpy;
            participant._mergeMessages = mergeMessagesStub;
            var otherMembers = ['2', '3', '4', '5', '6'];
            var message = participant.start(otherMembers);
            sinon.assert.calledOnce(cliquesSpy);
            sinon.assert.calledOnce(askeSpy);
            sinon.assert.calledOnce(mergeMessagesStub);
            assert.strictEqual(message, null);
        });
    });
    
    describe('#processMessage() method', function() {
        it('whole flow for 5 members', function() {
            var numMembers = 5;
            var initiator = 0;
            var members = [];
            var participants = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                var newMember = new ns.ProtocolHandler(i.toString(),
                                                       _td.RSA_PRIV_KEY,
                                                       _td.RSA_PUB_KEY,
                                                       _td.STATIC_PUB_KEY_DIR);
                participants.push(newMember);
            }
            var otherMembers = [];
            for (var i = 2; i <= numMembers; i++) {
                otherMembers.push(i.toString());
            }
            
            // Start.
            var message = participants[initiator].start(otherMembers);
            
            // ASKE upflow.
            while (message.dest !== '') {
                var nextId = message.members.indexOf(message.dest);
                message = participants[nextId].processMessage(message);
            }
            
//            // ASKE downflow for all.
//            var sid = null;
//            var nextMessages = []; 
//            while (message !== undefined) {
//                for (var i = 0; i < numMembers; i++) {
//                    var participant = participants[i];
//                    var nextMessage = participant.downflow(message);
//                    if (nextMessage !== null) {
//                        nextMessages.push(nextMessage);
//                    }
//                    assert.strictEqual(participant.id, members[i]);
//                    assert.deepEqual(participant.members, members);
//                    if (!sid) {
//                        sid = participant.sessionId;
//                    } else {
//                        assert.strictEqual(participant.sessionId, sid);
//                    }
//                }
//                message = nextMessages.shift();
//            }
//            for (var i = 0; i < participants.length; i++) {
//                assert.ok(participants[i].isSessionAcknowledged());
//            }
        });
    });

    
//        it('start the IKA without members', function() {
//            var participant = new ns.CliquesMember('1');
//            assert.throws(function() { participant.ika([]); },
//                          'No members to add.');
//        });
});
