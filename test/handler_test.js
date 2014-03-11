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

(function() {
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
            it('processing for an upflow message', function() {
                var message = { source: '1', dest: '2', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [null, []], nonces: ['foo'],
                                pubKeys: ['foo'], sessionSignature: null };
                var compare = { source: '2', dest: '3', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], []], nonces: ['foo', 'bar'],
                                pubKeys: ['foo', 'bar'], sessionSignature: null };
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var output = participant.processMessage(message);
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.agreement, compare.agreement);
                assert.strictEqual(output.flow, compare.flow);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.strictEqual(output.sessionSignature, compare.sessionSignature);
            });
            
            it('processing for last upflow message', function() {
                var message = { source: '4', dest: '5', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4'],
                                sessionSignature: null };
                var compare = { source: '5', dest: '', agreement: 'initial',
                                flow: 'downflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.ProtocolHandler('5',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var output = participant.processMessage(message);
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.agreement, compare.agreement);
                assert.strictEqual(output.flow, compare.flow);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.ok(output.sessionSignature);
            });
            
//            it('processing for a downflow message', function() {
//                var message = { source: '5', dest: '', agreement: 'initial',
//                                flow: 'downflow', members: ['1', '2', '3', '4', '5'],
//                                intKeys: [[], [], [], [], []],
//                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
//                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
//                                sessionSignature: 'bar' };
//                var compare = { source: '2', dest: '' };
//                var participant = new ns.ProtocolHandler('2',
//                                                         _td.RSA_PRIV_KEY,
//                                                         _td.RSA_PUB_KEY,
//                                                         _td.STATIC_PUB_KEY_DIR);
//                participant.cliquesMember.members = message.members;
//                var output = participant.processMessage(message);
//                dump(output);
//                assert.strictEqual(output.source, compare.source);
//                assert.strictEqual(output.dest, compare.dest);
////                assert.strictEqual(output.agreement, compare.agreement);
////                assert.strictEqual(output.flow, compare.flow);
////                assert.deepEqual(output.members, compare.members);
////                assert.lengthOf(output.intKeys, compare.intKeys.length);
////                assert.lengthOf(output.nonces, compare.nonces.length);
////                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
////                assert.ok(output.sessionSignature);
//            });
            
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
                
                // Upflow.
                while (message.dest !== '') {
                    var nextId = message.members.indexOf(message.dest);
                    message = participants[nextId].processMessage(message);
                }
                
                // Downflow for all.
                var nextMessages = []; 
                while (message !== undefined) {
                    for (var i = 0; i < participants.length; i++) {
                        var participant = participants[i];
                        if (members.indexOf(participant.id) < 0) {
                            continue;
                        }
                        var nextMessage = participant.processMessage(message);
                        if (nextMessage !== null) {
                            nextMessages.push(nextMessage);
                        }
                        assert.deepEqual(participant.cliquesMember.members, members);
                        assert.deepEqual(participant.askeMember.members, members);
                    }
                    message = nextMessages.shift();
                }
//                for (var i = 0; i < participants.length; i++) {
//                    var participant = participants[i];
//                    if (members.indexOf(participant.id) < 0) {
//                        continue;
//                    }
//                    assert.ok(participant.isSessionAcknowledged());
//                }
            });
        });
    
        
    //        it('start the IKA without members', function() {
    //            var participant = new ns.CliquesMember('1');
    //            assert.throws(function() { participant.ika([]); },
    //                          'No members to add.');
    //        });
    });
})();
