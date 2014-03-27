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
    var _echo = function(x) { return x; };
    
    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;
    
    beforeEach(function() {
        sandbox = sinon.sandbox.create();
    });
    
    afterEach(function() {
        sandbox.restore();
    });
    
    function _stripProtoFromMessage(message) {
        var _PROTO_STRING = '?mpENC:';
        if (!message) {
            return null;
        }
        return atob(message.substring(_PROTO_STRING.length, message.length -1));
    }
    
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
            
            it('merge the messages', function() {
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
            
            it('merge the messages for ASKE only', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var askeMessage = {source: '3', dest: '', flow: 'downflow',
                                   members: ['1', '2', '3', '4', '5', '6'],
                                   nonces: null, pubKeys: null, sessionSignature: null};
                var message = participant._mergeMessages(null, askeMessage);
                assert.strictEqual(message.source, '1');
                assert.strictEqual(message.dest, askeMessage.dest);
                assert.strictEqual(message.flow, askeMessage.flow);
                assert.deepEqual(message.members, askeMessage.members);
                assert.deepEqual(message.intKeys, null);
                assert.deepEqual(message.nonces, askeMessage.nonces);
                assert.deepEqual(message.pubKeys, askeMessage.pubKeys);
                assert.strictEqual(message.sessionSignature, askeMessage.sessionSignature);
            });
            
            it('merge the messages for CLIQUES only', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var cliquesMessage = {source: '1', dest: '', agreement: 'aka', flow: 'downflow',
                                      members: ['1', '2', '3', '4', '5'], intKeys: null};
                var message = participant._mergeMessages(cliquesMessage, null);
                assert.strictEqual(message.source, '1');
                assert.strictEqual(message.dest, cliquesMessage.dest);
                assert.strictEqual(message.flow, cliquesMessage.flow);
                assert.strictEqual(message.agreement, 'auxilliary');
                assert.deepEqual(message.members, cliquesMessage.members);
                assert.deepEqual(message.intKeys, cliquesMessage.intKeys);
            });
            
            it('merge the messages for final case (no messages)', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var message = participant._mergeMessages(null, undefined);
                assert.strictEqual(message, null);
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
        
        describe('#start() method', function() {
            it('start/initiate a group session', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var cliquesSpy = sinon.spy();
                var askeSpy = sinon.spy();
                var mergeMessagesStub = sinon.stub().returns(null);
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
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
        
        describe('#join() method', function() {
            it('join empty member list', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                assert.throws(function() { participant.join([]); },
                              'No members to add.');
            });
            
            it('add members to group', function() {
                var participant = new ns.ProtocolHandler('1',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var cliquesSpy = sinon.spy();
                var askeSpy = sinon.spy();
                var mergeMessagesStub = sinon.stub().returns(null);
                participant.cliquesMember.akaJoin = cliquesSpy;
                participant.askeMember.join = askeSpy;
                participant._mergeMessages = mergeMessagesStub;
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                var otherMembers = ['6', '7'];
                var message = participant.join(otherMembers);
                sinon.assert.calledOnce(cliquesSpy);
                sinon.assert.calledOnce(askeSpy);
                sinon.assert.calledOnce(mergeMessagesStub);
                assert.strictEqual(message, null);
            });
        });
        
        describe('#exclude() method', function() {
            it('exclude empty member list', function() {
                var participant = new ns.ProtocolHandler('3',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                assert.throws(function() { participant.exclude([]); },
                              'No members to exclude.');
            });
            
            it('exclude self', function() {
                var participant = new ns.ProtocolHandler('3',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                assert.throws(function() { participant.exclude(['3', '5']); },
                              'Cannot exclude mysefl.');
            });
            
            it('exclude members', function() {
                var participant = new ns.ProtocolHandler('3',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var cliquesSpy = sinon.spy();
                var askeSpy = sinon.spy();
                var mergeMessagesStub = sinon.stub().returns(null);
                participant.cliquesMember.akaExclude = cliquesSpy;
                participant.askeMember.exclude = askeSpy;
                participant._mergeMessages = mergeMessagesStub;
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                var message = participant.exclude(['1', '4']);
                sinon.assert.calledOnce(cliquesSpy);
                sinon.assert.calledOnce(askeSpy);
                sinon.assert.calledOnce(mergeMessagesStub);
                assert.strictEqual(message, null);
            });
        });
        
        describe('#refresh() method', function() {
            it('refresh own private key using aka', function() {
                var participant = new ns.ProtocolHandler('3',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var cliquesSpy = sinon.spy();
                var mergeMessagesStub = sinon.stub().returns(null);
                participant.cliquesMember.akaRefresh = cliquesSpy;
                participant._mergeMessages = mergeMessagesStub;
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                var message = participant.refresh();
                sinon.assert.calledOnce(cliquesSpy);
                sinon.assert.calledOnce(mergeMessagesStub);
                assert.strictEqual(message, null);
            });
        });
        
        describe('#processKeyingMessage() method', function() {
            it('processing for an upflow message', function() {
                var message = { source: '1', dest: '2', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [null, []], debugKeys: [null, '1*G'],
                                nonces: ['foo'], pubKeys: ['foo'],
                                sessionSignature: null };
                var compare = { source: '2', dest: '3', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], []], debugKeys: ['2*G', '1*G', '2*1*G'],
                                nonces: ['foo', 'bar'], pubKeys: ['foo', 'bar'],
                                sessionSignature: null };
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                sandbox.stub(mpenc.codec, 'decodeMessageContent', _echo);
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                var output = participant.processKeyingMessage(message);
                assert.strictEqual(output.source, compare.source);
                assert.strictEqual(output.dest, compare.dest);
                assert.strictEqual(output.agreement, compare.agreement);
                assert.strictEqual(output.flow, compare.flow);
                assert.deepEqual(output.members, compare.members);
                assert.lengthOf(output.intKeys, compare.intKeys.length);
                assert.deepEqual(output.debugKeys, compare.debugKeys);
                assert.lengthOf(output.nonces, compare.nonces.length);
                assert.lengthOf(output.pubKeys, compare.pubKeys.length);
                assert.strictEqual(output.sessionSignature, compare.sessionSignature);
            });
            
            it('processing for last upflow message', function() {
                var message = { source: '4', dest: '5', agreement: 'initial',
                                flow: 'upflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['', '', '', '', ''],
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
                sandbox.stub(mpenc.codec, 'decodeMessageContent', _echo);
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                var output = participant.processKeyingMessage(message);
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
            
            it('processing for a downflow message', function() {
                var message = { source: '5', dest: '', agreement: 'initial',
                                flow: 'downflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [[], [], [], [], []],
                                debugKeys: ['5*4*3*2*G', '5*4*3*1*G', '5*4*2*1*G',
                                            '5*3*2*1*G', '4*3*2*1*G'],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.ProtocolHandler('2',
                                                       _td.RSA_PRIV_KEY,
                                                       _td.RSA_PUB_KEY,
                                                       _td.STATIC_PUB_KEY_DIR);
                var cliquesUpflowSpy = sinon.spy();
                var cliquesDownflowSpy = sinon.spy();
                participant.cliquesMember.upflow = cliquesUpflowSpy;
                participant.cliquesMember.downflow = cliquesDownflowSpy;
                var askeUpflowSpy = sinon.spy();
                var askeDownflowSpy = sinon.spy();
                participant.askeMember.upflow = askeUpflowSpy;
                participant.askeMember.downflow = askeDownflowSpy;
                var mergeMessagesSpy = sinon.spy();
                participant._mergeMessages = mergeMessagesSpy;
                sandbox.stub(mpenc.codec, 'decodeMessageContent', _echo);
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                participant.processKeyingMessage(message);
                assert.strictEqual(cliquesUpflowSpy.callCount, 0);
                assert.strictEqual(askeUpflowSpy.callCount, 0);
                sinon.assert.calledOnce(cliquesDownflowSpy);
                sinon.assert.calledOnce(askeDownflowSpy);
                sinon.assert.calledOnce(mergeMessagesSpy);
            });
            
            it('processing for a downflow message after CLIQUES finish', function() {
                var message = { source: '5', dest: '', agreement: 'initial',
                                flow: 'downflow', members: ['1', '2', '3', '4', '5'],
                                intKeys: [], debugKeys: [],
                                nonces: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                pubKeys: ['foo1', 'foo2', 'foo3', 'foo4', 'foo5'],
                                sessionSignature: 'bar' };
                var participant = new ns.ProtocolHandler('2',
                                                       _td.RSA_PRIV_KEY,
                                                       _td.RSA_PUB_KEY,
                                                       _td.STATIC_PUB_KEY_DIR);
                var cliquesUpflowSpy = sinon.spy();
                var cliquesDownflowSpy = sinon.spy();
                participant.cliquesMember.upflow = cliquesUpflowSpy;
                participant.cliquesMember.downflow = cliquesDownflowSpy;
                var askeUpflowSpy = sinon.spy();
                var askeDownflowSpy = sinon.spy();
                participant.askeMember.upflow = askeUpflowSpy;
                participant.askeMember.downflow = askeDownflowSpy;
                var mergeMessagesSpy = sinon.spy();
                participant._mergeMessages = mergeMessagesSpy;
                sandbox.stub(mpenc.codec, 'decodeMessageContent', _echo);
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                participant.processKeyingMessage(message);
                assert.strictEqual(cliquesUpflowSpy.callCount, 0);
                assert.strictEqual(askeUpflowSpy.callCount, 0);
                assert.strictEqual(cliquesDownflowSpy.callCount, 0);
                sinon.assert.calledOnce(askeDownflowSpy);
                sinon.assert.calledOnce(mergeMessagesSpy);
            });
        });
        
        describe('#processMessage() method', function() {
            it('on plain text message', function() {
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.processMessage('Pōkarekare ana ngā wai o Waitemata, whiti atu koe hine marino ana e.');
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0].substring(0, 9),
                                   '?mpENCv' + mpenc.VERSION.charCodeAt(0) + '?');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'info');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'Received unencrypted message, requesting encryption.');
            });
            
            it('on error message', function() {
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                participant.processMessage('?mpENC Error:Hatschi!');
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'error');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'Error in mpEnc protocol: Hatschi!');
            });
            
            it('on keying message', function() {
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                
                sandbox.stub(mpenc.codec, 'decodeMessageContent').returns('foo');
                participant.processKeyingMessage = sinon.stub().returns('foo');
                sandbox.stub(mpenc.codec, 'encodeMessage', _echo);
                participant.processMessage('?mpENC:Zm9v.');
                sinon.assert.calledOnce(mpenc.codec.decodeMessageContent);
                sinon.assert.calledOnce(participant.processKeyingMessage);
                sinon.assert.calledOnce(mpenc.codec.encodeMessage);
                assert.lengthOf(participant.protocolOutQueue, 1);
                assert.strictEqual(participant.protocolOutQueue[0], 'foo');
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 0);
            });
            
            it('on data message', function() {
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                
                sandbox.stub(mpenc.codec, 'decodeMessageContent').returns(_td.DATA_MESSAGE_CONTENT);
                participant.processMessage(_td.DATA_MESSAGE_WIRE);
                sinon.assert.calledOnce(mpenc.codec.decodeMessageContent);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'message');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'foo');
            });
            
            it('on data message, invalid signature', function() {
                var participant = new ns.ProtocolHandler('2',
                                                         _td.RSA_PRIV_KEY,
                                                         _td.RSA_PUB_KEY,
                                                         _td.STATIC_PUB_KEY_DIR);
                var decodedContent = mpenc.utils.clone(_td.DATA_MESSAGE_CONTENT);
                decodedContent.signatureOk = false;
                sandbox.stub(mpenc.codec, 'decodeMessageContent').returns(decodedContent);
                participant.processMessage(_td.DATA_MESSAGE_WIRE);
                sinon.assert.calledOnce(mpenc.codec.decodeMessageContent);
                assert.lengthOf(participant.protocolOutQueue, 0);
                assert.lengthOf(participant.messageOutQueue, 0);
                assert.lengthOf(participant.uiQueue, 1);
                assert.strictEqual(participant.uiQueue[0].type, 'error');
                assert.strictEqual(participant.uiQueue[0].message,
                                   'Signature of received message invalid.');
            });
            
//            it('on query message', function() {
//                var participant = new ns.ProtocolHandler('2',
//                                                         _td.RSA_PRIV_KEY,
//                                                         _td.RSA_PUB_KEY,
//                                                         _td.STATIC_PUB_KEY_DIR);
//                participant.processMessage('?mpENCv' + mpenc.VERSION.charCodeAt(0) + '?foo.');
//                assert.lengthOf(participant.protocolOutQueue, 1);
//                assert.strictEqual(participant.protocolOutQueue[0], 'xxx');
//                assert.lengthOf(participant.messageOutQueue, 0);
//                assert.lengthOf(participant.uiQueue, 0);
//            });
            
            it('whole flow for 5 members, 2 joining, 2 others leaving, refresh', function() {
//                var numMembers = 5;
//                var initiator = 0;
//                var members = [];
//                var participants = [];
//                for (var i = 1; i <= numMembers; i++) {
//                    members.push(i.toString());
//                    var newMember = new ns.ProtocolHandler(i.toString(),
//                                                           _td.RSA_PRIV_KEY,
//                                                           _td.RSA_PUB_KEY,
//                                                           _td.STATIC_PUB_KEY_DIR);
//                    participants.push(newMember);
//                }
//                var otherMembers = [];
//                for (var i = 2; i <= numMembers; i++) {
//                    otherMembers.push(i.toString());
//                }
//                
//                // Start.
//                var message = participants[initiator].start(otherMembers);
//                var message_js = mpenc.codec.decodeMessageContent(_stripProtoFromMessage(message));
//                
//                // Upflow.
//                while (message && message_js.dest !== null) {
//                    var nextId = message_js.members.indexOf(message_js.dest);
//                    dump(nextId);
//                    message = participants[nextId].processMessage(message);
//                    message_js = mpenc.codec.decodeMessageContent(_stripProtoFromMessage(message));
//                }
                
//                // Downflow for all.
//                var nextMessages = [];
//                while (message_js) {
//                    for (var i = 0; i < participants.length; i++) {
//                        var participant = participants[i];
//                        if (members.indexOf(participant.id) < 0) {
//                            continue;
//                        }
//                        var nextMessage = participant.processMessage(message);
//                        if (nextMessage) {
//                            nextMessages.push(mpenc.utils.clone(nextMessage));
//                        }
//                        assert.deepEqual(participant.cliquesMember.members, members);
//                        assert.deepEqual(participant.askeMember.members, members);
//                    }
//                    message = nextMessages.shift();
//                    message_js = mpenc.codec.decodeMessageContent(message);
//                }
//                var keyCheck = null;
//                for (var i = 0; i < participants.length; i++) {
//                    var participant = participants[i];
//                    if (members.indexOf(participant.id) < 0) {
//                        continue;
//                    }
//                    if (!keyCheck) {
//                        keyCheck = participant.cliquesMember.groupKey;
//                    } else {
//                        assert.strictEqual(participant.cliquesMember.groupKey, keyCheck);
//                    }
//                    assert.ok(participant.askeMember.isSessionAcknowledged());
//                }
//                
//                // Join two new guys.
//                var newMembers = ['6', '7'];
//                members = members.concat(newMembers);
//                for (var i = 0; i < newMembers.length; i++) {
//                    var newMember = new ns.ProtocolHandler(newMembers[i],
//                                                           _td.RSA_PRIV_KEY,
//                                                           _td.RSA_PUB_KEY,
//                                                           _td.STATIC_PUB_KEY_DIR);
//                    participants.push(newMember);
//                }
//                
//                // '4' starts upflow for join.
//                message = participants[3].join(newMembers);
//                message_js = mpenc.codec.decodeMessageContent(message);
//                
//                // Upflow for join.
//                while (message_js.dest !== null) {
//                    var nextId = message_js.members.indexOf(message_js.dest);
//                    message = participants[nextId].processMessage(message);
//                    message_js = mpenc.codec.decodeMessageContent(message);
//                }
//                
//                // Downflow for all.
//                nextMessages = [];
//                while (message_js) {
//                    for (var i = 0; i < participants.length; i++) {
//                        var participant = participants[i];
//                        if (members.indexOf(participant.id) < 0) {
//                            continue;
//                        }
//                        var nextMessage = participant.processMessage(message);
//                        if (nextMessage) {
//                            nextMessages.push(mpenc.utils.clone(nextMessage));
//                        }
//                        assert.deepEqual(participant.cliquesMember.members, members);
//                        assert.deepEqual(participant.askeMember.members, members);
//                    }
//                    message = nextMessages.shift();
//                    message_js = mpenc.codec.decodeMessageContent(message);
//                }
//                keyCheck = null;
//                for (var i = 0; i < participants.length; i++) {
//                    var participant = participants[i];
//                    if (members.indexOf(participant.id) < 0) {
//                        continue;
//                    }
//                    if (!keyCheck) {
//                        keyCheck = participant.cliquesMember.groupKey;
//                    } else {
//                        assert.strictEqual(participant.cliquesMember.groupKey, keyCheck);
//                    }
//                    assert.ok(participant.askeMember.isSessionAcknowledged());
//                }
//                
//                // '3' excludes two members.
//                var toExclude = ['1', '4'];
//                members.splice(members.indexOf('1'), 1);
//                members.splice(members.indexOf('4'), 1);
//                message = participants[2].exclude(toExclude);
//                message_js = mpenc.codec.decodeMessageContent(message);
//                
//                // Downflow for exclude.
//                nextMessages = [];
//                while (message_js) {
//                    for (var i = 0; i < participants.length; i++) {
//                        var participant = participants[i];
//                        if (members.indexOf(participant.id) < 0) {
//                            continue;
//                        }
//                        var nextMessage = participant.processMessage(message);
//                        if (nextMessage) {
//                            nextMessages.push(mpenc.utils.clone(nextMessage));
//                        }
//                        assert.deepEqual(participant.cliquesMember.members, members);
//                        assert.deepEqual(participant.askeMember.members, members);
//                    }
//                    message = nextMessages.shift();
//                    message_js = mpenc.codec.decodeMessageContent(message);
//                }
//                keyCheck = null;
//                for (var i = 0; i < participants.length; i++) {
//                    var participant = participants[i];
//                    if (members.indexOf(participant.id) < 0) {
//                        continue;
//                    }
//                    if (!keyCheck) {
//                        keyCheck = participant.cliquesMember.groupKey;
//                    } else {
//                        assert.strictEqual(participant.cliquesMember.groupKey, keyCheck);
//                    }
//                    assert.ok(participant.askeMember.isSessionAcknowledged());
//                }
//                
//                // '2' initiates a key refresh.
//                var oldKey = participants[1].cliquesMember.groupKey;
//                message = participants[1].refresh();
//                message_js = mpenc.codec.decodeMessageContent(message);
//                
//                // Downflow for refresh.
//                nextMessages = [];
//                while (message_js) {
//                    for (var i = 0; i < participants.length; i++) {
//                        var participant = participants[i];
//                        if (members.indexOf(participant.id) < 0) {
//                            continue;
//                        }
//                        var nextMessage = participant.processMessage(message);
//                        if (nextMessage) {
//                            nextMessages.push(mpenc.utils.clone(nextMessage));
//                        }
//                        assert.deepEqual(participant.cliquesMember.members, members);
//                        assert.deepEqual(participant.askeMember.members, members);
//                    }
//                    message = nextMessages.shift();
//                    message_js = mpenc.codec.decodeMessageContent(message);
//                }
//                keyCheck = null;
//                for (var i = 0; i < participants.length; i++) {
//                    var participant = participants[i];
//                    if (members.indexOf(participant.id) < 0) {
//                        continue;
//                    }
//                    if (!keyCheck) {
//                        keyCheck = participant.cliquesMember.groupKey;
//                    } else {
//                        assert.strictEqual(participant.cliquesMember.groupKey, keyCheck);
//                    }
//                    assert.notStrictEqual(participant.cliquesMember.groupKey, oldKey);
//                    assert.ok(participant.askeMember.isSessionAcknowledged());
//                }
            });
        });
    });
})();
