/**
 * @fileOverview
 * Implementation of an authenticated Signature Key Exchange scheme.
 */

"use strict";

/**
 * @namespace
 * Implementation of an authenticated Signature Key Exchange scheme.
 * 
 * @description
 * <p>Implementation of an authenticated Signature Key Exchange scheme.</p>
 * 
 * <p>
 * This scheme is trying to prevent replay attacks by the use of a nonce-based
 * session ID as described in </p>
 * 
 * <p>
 * Jens-Matthias Bohli and Rainer Steinwandt. 2006.<br/>
 * "Deniable Group Key Agreement."<br/>
 * VIETCRYPT 2006, LNCS 4341, pp. 298-311.</p>
 * 
 * <p>
 * This implementation is using the Edwards25519 for an ECDSA signature
 * mechanism to complement the Curve25519-based group key agreement.</p>
 */
mpenc.ske = {};

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

/**
 * Carries message content for the authenticated signature key exchange.
 * 
 * @constructor
 * @param source
 *     Message originator (from).
 * @param dest
 *     Message destination (to).
 * @param msgType
 *     Message type.
 * @param members
 *     List (array) of all participating members.
 * @param nonces
 *     List (array) of all participants' nonces.
 * @param pubKeys
 *     List (array) of all participants' ephemeral public keys.
 * @returns {SignatureKeyExchangeMessage}
 */
mpenc.ske.SignatureKeyExchangeMessage = function(source, dest, msgType,
                                                 members, nonces, pubKeys) {
    this.source = source || '';
    this.dest = dest || '';
    this.msgType = msgType || '';
    this.members = members || [];
    this.nonces = nonces || [];
    this.pubKeys = pubKeys || [];
    
    return this;
};


/**
 * Implementation of the authenticated signature key exchange.
 * 
 * This implementation is using Edwards25519 ECDSA signatures.
 * 
 * @constructor
 * @param id {string}
 *     Member's identifier string.
 * @returns {SignatureKeyExchangeMember}
 * 
 * @property id {string}
 *     Member's identifier string.
 * @property members
 *     List of all participants.
 */
mpenc.ske.SignatureKeyExchangeMember = function(id) {
    this.id = id;
    this.members = [];
    this.ephemeralPrivKey = null;
    this.ephemeralPubKey = null;
    this.nonce = null;
    this.nonces = null;
    this.ephemeralPubKeys = null;
    this.sessionId = null;
    this.staticPrivKey = null;
    return this;
};


/**
 * Start the upflow for the the commit (nonce values and ephemeral public keys).
 * 
 * @param otherMembers
 *     Iterable of other members for the group (excluding self).
 * @returns {SignatureKeyExchangeMessage}
 * @method
 */
mpenc.ske.SignatureKeyExchangeMember.prototype.commit = function(otherMembers) {
    assert(otherMembers.length !== 0, 'No members to add.');
    this.ephemeralPubKeys = null;
    var startMessage = new mpenc.ske.SignatureKeyExchangeMessage(this.id,
                                                                 '', 'upflow');
    startMessage.members = [this.id].concat(otherMembers);
    this.nonce = null;
    this.nonces = [];
    this.ephemeralPubKeys = [];
    return this.upflow(startMessage);
};


/**
 * SKE upflow phase message processing.
 * 
 * @param message
 *     Received upflow message. See {@link SignatureKeyExchangeMessage}.
 * @returns {CSignatureKeyExchangeMessage}
 * @method
 */
mpenc.ske.SignatureKeyExchangeMember.prototype.upflow = function(message) {
    assert(mpenc.utils._noDuplicatesInList(message.members),
           'Duplicates in member list detected!');
    var myPos = message.members.indexOf(this.id);
    assert(myPos >= 0, 'Not member of this key exchange!');

    this.members = message.members;
    this.nonces = message.nonces;
    this.ephemeralPubKeys = message.pubKeys;
    
    // Make new nonce and ephemeral signing key pair.
    this.nonce = mpenc.utils._newKey08(256);
    this.nonces.push(this.nonce);
    this.ephemeralPrivKey = mpenc.utils._newKey08(512);
    this.ephemeralPubKey = djbec.publickey(this.ephemeralPrivKey);
    this.ephemeralPubKeys.push(this.ephemeralPubKey);
    
    // Add them to the message.
    message.nonces = this.nonces;
    message.pubKeys = this.pubKeys;
    
    // Pass on a message.
    if (myPos === this.members.length - 1) {
        // I'm the last in the chain:
        // Broadcast all intermediate keys.
        message.source = this.id;
        message.dest = '';
        message.flow = 'downflow';
    } else {
        // Pass a message on to the next in line.
        message.source = this.id;
        message.dest = this.members[myPos + 1];
    }
    message.nonces = this.nonces;
    message.pubKeys = this.ephemeralPubKeys;
    return message;
};
