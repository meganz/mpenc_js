/**
 * @module ske_test
 * 
 * Test of the ske module (Signature Key Exchange).
 */

/*
 * Created: 5 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

describe("module level", function() {
});

describe("SignatureKeyExchangeMember class", function() {
    describe('constructur', function() {
        it('simple constructor', function() {
            new SignatureKeyExchangeMember();
        });
    });
    
    describe('#commit() method', function() {
        it('start commit chain', function() {
            var participant = new SignatureKeyExchangeMember('1');
            var otherMembers = ['2', '3', '4', '5'];
            var spy = sinon.spy();
            participant.upflow = spy;
            participant.commit(otherMembers);
            sinon.assert.calledOnce(spy);
        });
        
        it('start commit chain without members', function() {
            var participant = new SignatureKeyExchangeMember('1');
            assert.throws(function() { participant.commit([]); },
                          'No members to add.');
        });
        
        it('start commit', function() {
            var participant = new SignatureKeyExchangeMember('1');
            var otherMembers = ['2', '3', '4', '5'];
            var startMessage = participant.commit(otherMembers);
            assert.strictEqual(startMessage.source, '1');
            assert.strictEqual(startMessage.dest, '2');
            assert.strictEqual(startMessage.msgType, 'upflow');
            assert.deepEqual(startMessage.members, ['1'].concat(otherMembers));
            assert.lengthOf(startMessage.nonces, 1);
            assert.lengthOf(startMessage.pubKeys, 1);
        });
    });
    
    describe('#upflow() method', function() {
        it('upflow duplicates in member list', function() {
            var participant = new SignatureKeyExchangeMember('1');
            var members = ['3', '1', '2', '3', '4', '5', '6'];
            var startMessage = new SignatureKeyExchangeMessage();
            startMessage.members = members;
            assert.throws(function() { participant.upflow(startMessage); },
                          'Duplicates in member list detected!');
        });
        
        it('upflow not in member list', function() {
            var participant = new SignatureKeyExchangeMember('1');
            var members = ['2', '3', '4', '5', '6'];
            var startMessage = new SignatureKeyExchangeMessage();
            startMessage.members = members;
            assert.throws(function() { participant.upflow(startMessage); },
                          'Not member of this key exchange!');
        });
        
        it('upflow, for initiator', function() {
            var participant = new SignatureKeyExchangeMember('1');
            var members = ['1', '2', '3', '4', '5'];
            var startMessage = new SignatureKeyExchangeMessage('1', '', 'upflow',
                                                               members);
            var message = participant.upflow(startMessage);
            assert.strictEqual(message.source, '1');
            assert.strictEqual(message.dest, '2');
            assert.deepEqual(message.members, members);
            assert.lengthOf(message.nonces, 1);
            assert.lengthOf(message.pubKeys, 1);
        });
        
//        it('TODO: remove this', function() {
//            //
//        });
    });
});
