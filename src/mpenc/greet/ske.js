/**
 * @fileOverview
 * Implementation of an authenticated Signature Key Exchange scheme.
 */

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "jodid25519",
], function(assert, utils, jodid25519) {
    "use strict";

    /**
     * @exports mpenc/greet/ske
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
    var ns = {};

    var _assert = assert.assert;

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

    var MAGIC_NUMBER = 'acksig';

    /**
     * Carries message content for the authenticated signature key exchange.
     *
     * @constructor
     * @param source
     *     Message originator (from).
     * @param dest
     *     Message destination (to).
     * @param flow
     *     Message type.
     * @param members
     *     List (array) of all participating members.
     * @param nonces
     *     List (array) of all participants' nonces.
     * @param pubKeys
     *     List (array) of all participants' ephemeral public keys.
     * @param sessionSignature
     *     Signature to acknowledge the session.
     * @returns {SignatureKeyExchangeMessage}
     *
     * @property source {string}
     *     Sender participant ID of message.
     * @property dest {string}
     *     Destination participatn ID of message (empty for broadcast).
     * @property flow {string}
     *     Flow direction of message ('up' or 'down').
     * @property members {Array}
     *     Participant IDs of members.
     * @property nonces {Array}
     *     Nonces of members.
     * @property pubKeys {Array}
     *     Ephemeral public signing key of members.
     * @property sessionSignature {string}
     *     Session acknowledgement signature using sender's static key.
     * @property signingKey {string}
     *     Ephemeral private signing key for session (upon quitting participation).
     */
    ns.SignatureKeyExchangeMessage = function(source, dest, flow, members,
                                              nonces, pubKeys, sessionSignature) {
        this.source = source || '';
        this.dest = dest || '';
        this.flow = flow || '';
        this.members = members || [];
        this.nonces = nonces || [];
        this.pubKeys = pubKeys || [];
        this.sessionSignature = sessionSignature || null;
        this.signingKey = null;

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
     * @property authenticatedMembers
     *     List of boolean authentication values for members.
     * @property ephemeralPrivKey
     *     Own ephemeral private signing key.
     * @property ephemeralPubKey
     *     Own ephemeral public signing key.
     * @property nonce
     *     Own nonce value for this session.
     * @property nonces
     *     Nonce values of members for this session.
     * @property ephemeralPubKeys
     *     Ephemeral signing keys for members.
     * @property sessionId
     *     Session ID of this session.
     * @property staticPrivKey
     *     Own static (long term) signing key.
     * @property staticPubKeyDir
     *     "Directory" of static public keys, using the participant ID as key.
     * @property oldEphemeralKeys
     *     "Directory" of previous participants' ephemeral keys, using the
     *     participant ID as key. The entries contain an object with one or more of
     *     the members `priv`, `pub` and `authenticated` (if the key was
     *     successfully authenticated).
     */
    ns.SignatureKeyExchangeMember = function(id) {
        this.id = id;
        this.members = [];
        this.authenticatedMembers = null;
        this.ephemeralPrivKey = null;
        this.ephemeralPubKey = null;
        this.nonce = null;
        this.nonces = null;
        this.ephemeralPubKeys = null;
        this.sessionId = null;
        this.staticPrivKey = null;
        this.staticPubKeyDir = null;
        this.oldEphemeralKeys = {};
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
    ns.SignatureKeyExchangeMember.prototype.commit = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');
        this.ephemeralPubKeys = null;
        var startMessage = new ns.SignatureKeyExchangeMessage(this.id, '', 'up');
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
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.upflow = function(message) {
        _assert(utils._noDuplicatesInList(message.members),
                'Duplicates in member list detected!');
        _assert(message.nonces.length <= message.members.length,
                'Too many nonces on ASKE upflow!');
        _assert(message.pubKeys.length <= message.members.length,
                'Too many pub keys on ASKE upflow!');
        var myPos = message.members.indexOf(this.id);
        _assert(myPos >= 0, 'Not member of this key exchange!');

        this.members = utils.clone(message.members);
        this.nonces = utils.clone(message.nonces);
        this.ephemeralPubKeys = utils.clone(message.pubKeys);

        // Make new nonce and ephemeral signing key pair.
        this.nonce = jodid25519.eddsa.generateKeySeed();
        this.nonces.push(this.nonce);
        if (!this.ephemeralPrivKey) {
            // Only generate a new key if we don't have one.
            // We might want to recover and just re-run the protocol.
            this.ephemeralPrivKey = jodid25519.eddsa.generateKeySeed();
        }
        this.ephemeralPubKey = jodid25519.eddsa.publicKey(this.ephemeralPrivKey);
        this.ephemeralPubKeys.push(this.ephemeralPubKey);

        // Clone message.
        message = utils.clone(message);

        // Pass on a message.
        if (myPos === this.members.length - 1) {
            // Compute my session ID.
            this.sessionId = ns._computeSid(this.members, this.nonces);
            // I'm the last in the chain:
            // Broadcast own session authentication.
            message.source = this.id;
            message.dest = '';
            message.flow = 'down';
            this.discardAuthentications();
            message.sessionSignature = this._computeSessionSig();
        } else {
            // Pass a message on to the next in line.
            message.source = this.id;
            message.dest = this.members[myPos + 1];
        }
        message.nonces = utils.clone(this.nonces);
        message.pubKeys = utils.clone(this.ephemeralPubKeys);
        return message;
    };


    /**
     * Computes a session acknowledgement signature sigma(m) of a message
     * m = (pid_i, E_i, k_i, sid) using the static private key.
     *
     * @returns
     *     Session signature.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype._computeSessionSig = function() {
        _assert(this.sessionId, 'Session ID not available.');
        _assert(this.ephemeralPubKey, 'No ephemeral key pair available.');
        var sessionAck = MAGIC_NUMBER + this.id + this.ephemeralPubKey
                       + this.nonce + this.sessionId;
        var hashValue = utils.sha256(sessionAck);
        return jodid25519.eddsa.sign(hashValue, this.staticPrivKey,
                                     this.staticPubKeyDir.get(this.id));
    };


    /**
     * Verifies a session acknowledgement signature sigma(m) of a message
     * m = (pid_i, E_i, k_i, sid) using the static public key.
     *
     * @param memberId
     *     Participant ID of the member to verify the signature against.
     * @param signature
     *     Session acknowledgement signature.
     * @returns
     *     Whether the signature verifies against the member's static public key.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype._verifySessionSig = function(memberId, signature) {
        _assert(this.sessionId, 'Session ID not available.');
        var memberPos = this.members.indexOf(memberId);
        _assert(memberPos >= 0, 'Member not in participants list.');
        _assert(this.ephemeralPubKeys[memberPos],
                "Member's ephemeral pub key missing.");
        _assert(this.staticPubKeyDir.get(memberId),
                "Member's static pub key missing.");
        var sessionAck = MAGIC_NUMBER + memberId + this.ephemeralPubKeys[memberPos]
                       + this.nonces[memberPos] + this.sessionId;
        var hashValue = utils.sha256(sessionAck);
        return jodid25519.eddsa.verify(signature, hashValue,
                                       this.staticPubKeyDir.get(memberId));
    };


    /**
     * SKE downflow phase message processing.
     *
     * Returns null for the case that it has sent a downflow message already.
     *
     * @param message
     *     Received downflow message. See {@link SignatureKeyExchangeMessage}.
     * @returns {SignatureKeyExchangeMessage} or null.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.downflow = function(message) {
        _assert(utils._noDuplicatesInList(message.members),
                'Duplicates in member list detected!');
        var myPos = message.members.indexOf(this.id);

        // Generate session ID for received information.
        var sid = ns._computeSid(message.members, message.nonces);

        // Is this a broadcast for a new session?
        var existingSession = (this.sessionId === sid);
        if (!existingSession) {
            this.members = utils.clone(message.members);
            this.nonces = utils.clone(message.nonces);
            this.ephemeralPubKeys = utils.clone(message.pubKeys);
            this.sessionId = sid;
            this.discardAuthentications();
        }

        // Verify the session authentication from sender.
        var isValid = this._verifySessionSig(message.source,
                                             message.sessionSignature);
        _assert(isValid, 'Authentication of member ' + message.source + ' failed.');
        var senderPos = message.members.indexOf(message.source);
        this.authenticatedMembers[senderPos] = true;

        if (existingSession) {
            // We've acknowledged already, so no more broadcasts from us.
            return null;
        }

        // Clone message.
        message = utils.clone(message);
        // We haven't acknowledged, yet, so pass on the message.
        message.source = this.id;
        message.sessionSignature = this._computeSessionSig();

        return message;
    };


    /**
     * Returns true if the authenticated signature key exchange is fully
     * acknowledged.
     *
     * @returns {bool}
     *     True on a valid session.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.isSessionAcknowledged = function() {
        if (this.authenticatedMembers && (this.authenticatedMembers.length > 0)) {
            return this.authenticatedMembers.every(function(item) { return item; });
        } else {
            return false;
        }
    };


    /**
     * Returns the ephemeral public signing key of a participant.
     *
     * @param participantId
     *     Participant ID of the member to query for.
     * @returns {string}
     *     The binary string of the key or `undefined` if unknown.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.getMemberEphemeralPubKey = function(participantId) {
        var index = this.members.indexOf(participantId);
        if (index >= 0) {
            return this.ephemeralPubKeys[index];
        } else {
            var record = this.oldEphemeralKeys[participantId];
            if (record) {
                return record.pub;
            }
        }
    };


    /**
     * Discard all authentications, and set only self to authenticated.
     *
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.discardAuthentications = function() {
        var myPos = this.members.indexOf(this.id);
        this.authenticatedMembers = utils._arrayMaker(this.members.length, false);
        this.authenticatedMembers[myPos] = true;
    }


    /**
     * Start a new upflow for joining new members.
     *
     * @param newMembers
     *     Iterable of new members to join the group.
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.join = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');
        var allMembers = this.members.concat(newMembers);
        _assert(utils._noDuplicatesInList(allMembers),
                'Duplicates in member list detected!');
        this.members = allMembers;
        this.discardAuthentications();

        // Pass a message on to the first new member to join.
        var startMessage = new ns.SignatureKeyExchangeMessage(this.id, '', 'up');
        startMessage.dest = newMembers[0];
        startMessage.members = utils.clone(allMembers);
        startMessage.nonces = utils.clone(this.nonces);
        startMessage.pubKeys = utils.clone(this.ephemeralPubKeys);

        return startMessage;
    };


    /**
     * Start a new downflow for excluding members.
     *
     * @param excludeMembers
     *     Iterable of members to exclude from the group.
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.exclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(utils._arrayIsSubSet(excludeMembers, this.members),
                'Members list to exclude is not a sub-set of previous members!');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        // Kick 'em.
        for (var i = 0; i < excludeMembers.length; i++) {
            var index = this.members.indexOf(excludeMembers[i]);
            this.oldEphemeralKeys[excludeMembers[i]] = {
                pub: this.ephemeralPubKeys[index] || null,
                authenticated: this.authenticatedMembers[index] || false,
            };
            this.members.splice(index, 1);
            this.nonces.splice(index, 1);
            this.ephemeralPubKeys.splice(index, 1);
        }

        // Need a new nonce to force a different SID on same participant sets.
        this.nonce = jodid25519.eddsa.generateKeySeed();
        var myPos = this.members.indexOf(this.id);
        this.nonces[myPos] = this.nonce;

        // Compute my session ID.
        this.sessionId = ns._computeSid(this.members, this.nonces);

        this.discardAuthentications();

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.SignatureKeyExchangeMessage(this.id, '', 'down');
        broadcastMessage.members = utils.clone(this.members);
        broadcastMessage.nonces = utils.clone(this.nonces);
        broadcastMessage.pubKeys = utils.clone(this.ephemeralPubKeys);
        broadcastMessage.sessionSignature = this._computeSessionSig();

        return broadcastMessage;
    };


    /**
     * Quit own participation and publish the ephemeral signing key.
     *
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.quit = function() {
        _assert(this.ephemeralPrivKey !== null, 'Not participating.');

        // Kick myself out.
        var myPos = this.members.indexOf(this.id);
        this.oldEphemeralKeys[this.id] = {
            pub: this.ephemeralPubKey,
            priv: this.ephemeralPrivKey,
            authenticated: false
        };
        if (this.authenticatedMembers) {
            this.oldEphemeralKeys[this.id].authenticated = this.authenticatedMembers[myPos];
            this.authenticatedMembers.splice(myPos, 1);
        }
        if (this.members) {
            this.members.splice(myPos, 1);
        }
        if (this.nonces) {
            this.nonces.splice(myPos, 1);
        }
        if (this.ephemeralPubKeys) {
            this.ephemeralPubKeys.splice(myPos, 1);
        }

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.SignatureKeyExchangeMessage(this.id, '', 'down');
        broadcastMessage.signingKey = this.oldEphemeralKeys[this.id].priv;

        return broadcastMessage;
    };


    /**
     * Fully re-run whole key agreements, but retain the ephemeral signing key.
     *
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.fullRefresh = function() {
        // Store away old ephemeral keys of members.
        for (var i = 0; i < this.members.length; i++) {
            if (this.ephemeralPubKeys && (i < this.ephemeralPubKeys.length)) {
                this.oldEphemeralKeys[this.members[i]] = {
                    pub: this.ephemeralPubKeys[i],
                    priv: null,
                };
                if (this.ephemeralPubKeys && (i < this.authenticatedMembers.length)) {
                    this.oldEphemeralKeys[this.members[i]].authenticated = this.authenticatedMembers[i];
                } else {
                    this.oldEphemeralKeys[this.members[i]].authenticated = false;
                }
            }
        }
        this.oldEphemeralKeys[this.id].priv = this.ephemeralPrivKey;

        // Force complete new exchange of session info.
        this.sessionId = null;

        // Start with the other members.
        var otherMembers = utils.clone(this.members);
        var myPos = otherMembers.indexOf(this.id);
        otherMembers.splice(myPos, 1);
        return this.commit(otherMembers);
    };


    /**
     * Computes the session ID.
     *
     * @param members
     *     Members participating in protocol.
     * @param nonces
     *     Nonces of the members in matching order.
     * @returns
     *     Session ID as binary string.
     */
    ns._computeSid = function(members, nonces) {
        // Create a mapping to access sorted/paired items later.
        var mapping = {};
        for (var i = 0; i < members.length; i++) {
            mapping[members[i]] = nonces[i];
        }
        var sortedMembers = members.concat();
        sortedMembers.sort();

        // Compose the item chain.
        var pidItems = '';
        var nonceItems = '';
        for (var i = 0; i < sortedMembers.length; i++) {
            var pid = sortedMembers[i];
            if (pid) {
                pidItems += pid;
                nonceItems += mapping[pid];
            }
        }
        return utils.sha256(pidItems + nonceItems);
    };

    return ns;
});
