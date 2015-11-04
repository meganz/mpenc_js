/*
 * Created: 5 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2015 by Mega Limited, Auckland, New Zealand
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

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "jodid25519",
], function(assert, utils, jodid25519) {
    "use strict";

    /**
     * @exports mpenc/greet/ske
     * @private
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

    var MAGIC_NUMBER = 'acksig';

    /**
     * Carries message content for the authenticated signature key exchange.
     *
     * @constructor
     * @private
     * @param source {string}
     *     Message originator (from).
     * @param dest {string}
     *     Message destination (to).
     * @param flow {string}
     *     Message type.
     * @param members {Array<string>}
     *     List (array) of all participating members.
     * @param nonces {Array<string>}
     *     List (array) of all participants' nonces.
     * @param pubKeys {Array<string>}
     *     List (array) of all participants' ephemeral public keys.
     * @param sessionSignature {string}
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
     * @private
     * @param id {string}
     *     Member's identifier string.
     * @returns {SignatureKeyExchangeMember}
     *
     * @property id {string}
     *     Member's identifier string.
     * @property members {array<string>}
     *     List of all participants.
     * @property authenticatedMembers {array<boolean>}
     *     List of boolean authentication values for members.
     * @property ephemeralPrivKey {string}
     *     Own ephemeral private signing key.
     * @property ephemeralPubKey {string}
     *     Own ephemeral public signing key.
     * @property nonce {string}
     *     Own nonce value for this session.
     * @property nonces {array<string>}
     *     Nonce values of members for this session.
     * @property ephemeralPubKeys {array<string>}
     *     Ephemeral signing keys for members.
     * @property sessionId {string}
     *     Session ID of this session.
     * @property staticPrivKey {string}
     *     Own static (long term) signing key.
     * @property staticPubKeyDir {mpenc/handler.PubKeyDir}
     *     "Directory" of static public keys, using the participant ID as key.
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
        return this;
    };


    /**
     * Start the upflow for the the commit (nonce values and ephemeral public keys).
     *
     * @param otherMembers {array<string>}
     *     Other members for the group (excluding self).
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
     * @param message {SignatureKeyExchangeMessage}
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
     * @returns {string}
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
     * @param memberId {string}
     *     Participant ID of the member to verify the signature against.
     * @param signature {string}
     *     Session acknowledgement signature.
     * @returns {boolean}
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
     * @param message {SignatureKeyExchangeMessage}
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
        _assert(isValid, 'Session authentication by member ' + message.source + ' failed.');
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
     * @returns {boolean}
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
     * Returns the ids of the members yet to acknowledge to us.
     *
     * @returns {array<string>} Participant ids.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.yetToAuthenticate = function() {
        var memNotAck = [];
        for (var x = 0; x < this.authenticatedMembers.length; x++) {
            if (!this.authenticatedMembers[x]) {
                memNotAck.push(this.members[x]);
            }
        }
        return memNotAck;
    };

    /**
     * Returns the ephemeral public signing key of a participant.
     *
     * @param participantId {string}
     *     Participant ID of the member to query for.
     * @returns {string}
     *     The binary string of the key or `undefined` if unknown.
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.getMemberEphemeralPubKey = function(participantId) {
        var index = this.members.indexOf(participantId);
        if (index >= 0) {
            return this.ephemeralPubKeys[index];
        }
    };


    /**
     * Discard all authentications, and set only self to authenticated.
     *
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.discardAuthentications = function() {
        var myPos = this.members.indexOf(this.id);
        this.authenticatedMembers = utils.arrayMaker(this.members.length, false);
        this.authenticatedMembers[myPos] = true;
    };


    /**
     * Start a new upflow for joining new members.
     *
     * @param newMembers {array<string>}
     *     New members to join the group.
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

        this.nonce = jodid25519.eddsa.generateKeySeed();
        var myPos = this.members.indexOf(this.id);
        this.nonces[myPos] = this.nonce;

        // Compute my session ID.
        this.sessionId = ns._computeSid(this.members, this.nonces);

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
     * @param excludeMembers {array<string>}
     *     Members to exclude from the group.
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
     * Quit own participation.
     *
     * @returns {SignatureKeyExchangeMessage}
     * @method
     */
    ns.SignatureKeyExchangeMember.prototype.quit = function() {
        _assert(this.ephemeralPrivKey !== null, 'Not participating.');

        // Kick myself out.
        var myPos = this.members.indexOf(this.id);
        if (this.authenticatedMembers) {
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
        // TODO: it is probably not appropriate to publish the signing key at this stage.
        //broadcastMessage.signingKey = this.ephemeralPrivKey;
        //
        // The server could pretend that Alice hasn't left, drop her QUIT message,
        // then carry on signing messages on behalf of her.
        //
        // OTR only publishes a previous key, after agreeing to a new key
        // https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html "revealing mac keys"
        // To force this, the user must click "end conversation" explicitly
        //
        // We need logic something along the lines of:
        //
        // - detect an event E that is authenticated via means independently of
        //   key K (but perhaps both can be 1-way derived from a common ancestor)
        // - write code that only ever publishes K *after* E
        // - then everyone can assume: everything authenticated by K that E
        //   references (e.g. via hash pointers) is authentic
        // - if we see K being published, then we need to go through previously
        //   received things that was signed by K, and maybe *remove* their
        //   authenticated status.
        //   - if we have received E, then everything not referenced by E is unauthenticated
        //   - if we have not yet received E, then everything is unauthenticated
        //      - we could publish K inside E (authenticated but not encrypted)
        //        which would remove this special case

        return broadcastMessage;
    };


    /**
     * Computes the session ID.
     *
     * @param members {array<string>}
     *     Members participating in protocol.
     * @param nonces {array<string>}
     *     Nonces of the members in matching order.
     * @returns {string}
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
