/*
 * Created: 20 Jan 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "asmcrypto",
    "jodid25519"
], function(assert, utils, asmCrypto, jodid25519) {
    "use strict";

    /**
     * @exports mpenc/greet/cliques
     * @private
     * @description
     * <p>Implementation of group key agreement based on CLIQUES.</p>
     *
     * <p>
     * Michael Steiner, Gene Tsudik, and Michael Waidner. 2000.<br/>
     * "Key Agreement in Dynamic Peer Groups."<br/>
     * IEEE Trans. Parallel Distrib. Syst. 11, 8 (August 2000), 769-780.<br/>
     * DOI=10.1109/71.877936</p>
     *
     * <p>This implementation is using the Curve25519 for ECDH mechanisms as a base
     * extended for group key agreement.</p>
     */
    var ns = {};

    var _assert = assert.assert;


    /**
     * Derive the shared confidentiality group key.
     *
     * The group key is a 32-byte string, half of which is later used for
     * AES-128. It is derived from the cardinal key, a x25519 public value,
     * using HKDF-SHA256.
     *
     * @param sharedCardinalKey {string} Input IKM for the HKDF. In mpENC, this
     *      is the x25519 public key result of the group key agreement.
     * @param [context] {string} Info string for the HKDF. In mpENC, this is
     *      set to the constant "mpenc group key".
     */
    ns.deriveGroupKey = function(sharedCardinalKey, context) {
        // equivalent to first block of HKDF, see RFC 5869
        context = context === undefined ? "mpenc group key" : context;
        var hmac = asmCrypto.HMAC_SHA256.bytes;
        return jodid25519.utils.bytes2string(
            hmac(context + "\x01", hmac(sharedCardinalKey, "")));
    };


    /**
     * Carries message content for the CLIQUES protocol.
     *
     * @param source
     *     Message originator (from).
     * @param dest
     *     Message destination (to).
     * @param agreement
     *     Type of key agreement. "ika" or "aka".
     * @param flow
     *     Direction of message flow. "up" or "down".
     * @param members
     *     List (array) of all participating members.
     * @param intKeys
     *     List (array) of intermediate keys to transmit.
     * @returns {CliquesMessage}
     * @constructor
     * @private
     *
     * @property source
     *     Message originator (from).
     * @property dest
     *     Message destination (to).
     * @property agreement
     *     Type of key agreement. "ika" or "aka".
     * @property flow
     *     Direction of message flow. "up" or "down".
     * @property members
     *     List (array) of all participating members.
     * @property intKeys
     *     List (array) of intermediate keys to transmit.
     */
    ns.CliquesMessage = function(source, dest, agreement, flow, members, intKeys) {
        this.source = source || '';
        this.dest = dest || '';
        this.agreement = agreement || '';
        this.flow = flow || '';
        this.members = members || [];
        this.intKeys = intKeys || [];
        return this;
    };


    /**
     * Implementation of group key agreement based on CLIQUES.
     *
     * This implementation is using the Curve25519 for ECDH mechanisms as a base
     * extended for group key agreement.
     *
     * @constructor
     * @private
     * @param id {string}
     *     Member's identifier string.
     * @returns {CliquesMember}
     *
     * @property id {string}
     *     Member's identifier string.
     * @property members
     *     List of all participants.
     * @property intKeys
     *     List (array) of intermediate keys for all participants. The key for
     *     each participant contains all others' contributions but the
     *     participant's one.
     * @property privKey
     *     This participant's private key.
     * @property groupKey
     *     Shared secret, the group key.
     */
    ns.CliquesMember = function(id) {
        this.id = id;
        this.members = [];
        this.intKeys = [];
        this.privKeyList = [];
        this.groupKey = null;

        return this;
    };


    /**
     * Start the IKA (Initial Key Agreement) procedure for the given members.
     *
     * @method
     * @param otherMembers
     *     Iterable of other members for the group (excluding self).
     * @returns {CliquesMessage}
     */
    ns.CliquesMember.prototype.ika = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');
        this.intKeys = null;
        this.privKeyList = [];
        var startMessage = new ns.CliquesMessage(this.id);
        startMessage.members = [this.id].concat(otherMembers);
        startMessage.agreement = 'ika';
        startMessage.flow = 'up';
        return this.upflow(startMessage);
    };


    /**
     * Start the AKA (Auxiliary Key Agreement) for joining new members.
     *
     * @method
     * @param newMembers
     *     Iterable of new members to join the group.
     * @returns {CliquesMessage}
     */
    ns.CliquesMember.prototype.akaJoin = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');
        var allMembers = this.members.concat(newMembers);
        _assert(utils._noDuplicatesInList(allMembers),
                'Duplicates in member list detected!');

        // Replace members list.
        this.members = allMembers;

        // Renew all keys.
        var cardinalKey = this._renewPrivKey();

        // Start of AKA upflow, so we can't be the last member in the chain.
        // Add the new cardinal key.
        this.intKeys.push(cardinalKey);

        // Pass a message on to the first new member to join.
        var startMessage = new ns.CliquesMessage(this.id);
        startMessage.members = allMembers;
        startMessage.dest = newMembers[0];
        startMessage.agreement = 'aka';
        startMessage.flow = 'up';
        startMessage.intKeys = this.intKeys;

        return startMessage;
    };


    /**
     * Start the AKA (Auxiliary Key Agreement) for excluding members.
     *
     * @method
     * @param excludeMembers
     *     Iterable of members to exclude from the group.
     * @returns {CliquesMessage}
     */
    ns.CliquesMember.prototype.akaExclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(utils._arrayIsSubSet(excludeMembers, this.members),
                'Members list to exclude is not a sub-set of previous members!');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        // Kick 'em.
        for (var i = 0; i < excludeMembers.length; i++) {
            var index = this.members.indexOf(excludeMembers[i]);
            this.members.splice(index, 1);
            this.intKeys.splice(index, 1);
        }

        // Renew all keys.
        var cardinalKey = this._renewPrivKey();

        // Discard old and make new group key.
        this.groupKey = ns.deriveGroupKey(cardinalKey);

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.CliquesMessage(this.id);
        broadcastMessage.members = this.members;
        broadcastMessage.agreement = 'aka';
        broadcastMessage.flow = 'down';
        broadcastMessage.intKeys = this.intKeys;

        return broadcastMessage;
    };


    /**
     * AKA (Auxiliary Key Agreement) for excluding members.
     *
     * For CLIQUES, there is no message flow involved.
     *
     * @method
     */
    ns.CliquesMember.prototype.akaQuit = function() {
        _assert(this.privKeyList.length !== 0, 'Not participating.');

        // Kick myself out.
        var myPos = this.members.indexOf(this.id);
        if (myPos >= 0) {
            this.members.splice(myPos, 1);
            this.intKeys = [];
            this.privKeyList = [];
        }
    };


    /**
     * Start the AKA (Auxiliary Key Agreement) for refreshing the own private key.
     *
     * @returns {CliquesMessage}
     * @method
     */
    ns.CliquesMember.prototype.akaRefresh = function() {
        // Renew all keys.
        var cardinalKey = this._renewPrivKey();

        // Discard old and make new group key.
        this.groupKey = ns.deriveGroupKey(cardinalKey);

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.CliquesMessage(this.id);
        broadcastMessage.members = this.members;
        broadcastMessage.agreement = 'aka';
        broadcastMessage.flow = 'down';
        broadcastMessage.intKeys = this.intKeys;

        return broadcastMessage;
    };


    /**
     * IKA/AKA upflow phase message processing.
     *
     * @method
     * @param message
     *     Received upflow message. See {@link CliquesMessage}.
     * @returns {CliquesMessage}
     */
    ns.CliquesMember.prototype.upflow = function(message) {
        _assert(utils._noDuplicatesInList(message.members),
                'Duplicates in member list detected!');
        _assert(message.intKeys.length <= message.members.length,
                'Too many intermediate keys on CLIQUES upflow!');

        this.members = message.members;
        this.intKeys = message.intKeys;
        if (this.intKeys.length === 0) {
            // We're the first, so let's initialise it.
            this.intKeys = [null];
        }

        // To not confuse _renewPrivKey() in full refresh situation.
        if (message.agreement === 'ika') {
            this.privKeyList = [];
        }

        // Renew all keys.
        var cardinalKey = this._renewPrivKey();
        var myPos = this.members.indexOf(this.id);

        // Clone message.
        message = utils.clone(message);
        if (myPos === this.members.length - 1) {
            // I'm the last in the chain:
            // Cardinal is secret key.
            this.groupKey = ns.deriveGroupKey(cardinalKey);
            this._setKeys(this.intKeys);
            // Broadcast all intermediate keys.
            message.source = this.id;
            message.dest = '';
            message.flow = 'down';
        } else {
            // Add the new cardinal key.
            this.intKeys.push(cardinalKey);
            // Pass a message on to the next in line.
            message.source = this.id;
            message.dest = this.members[myPos + 1];
        }
        message.intKeys = this.intKeys;
        return message;
    };


    /**
     * Renew the private key, update the set of intermediate keys and return
     * the new cardinal key.
     *
     * @returns
     *     Cardinal key.
     * @method
     * @private
     */
    ns.CliquesMember.prototype._renewPrivKey = function() {
        // Make a new private key.
        this.privKeyList.push(jodid25519.dh.generateKey());

        // Update intermediate keys.
        var myPos = this.members.indexOf(this.id);
        for (var i = 0; i < this.intKeys.length; i++) {
            if (i !== myPos) {
                var lastIndex = this.privKeyList.length - 1;
                this.intKeys[i] = jodid25519.dh.computeKey(this.privKeyList[lastIndex],
                                                           this.intKeys[i]);
            }
        }

        // New cardinal is "own" intermediate scalar multiplied with our private.
        var cardinalKey = ns._computeKeyList(this.privKeyList,
                                             this.intKeys[myPos]);
        return '' + cardinalKey;
    };

    /**
     * IKA downflow phase broadcast message receive.
     *
     * @method
     * @param message
     *     Received downflow broadcast message.
     */
    ns.CliquesMember.prototype.downflow = function(message) {
        _assert(utils._noDuplicatesInList(message.members),
                'Duplicates in member list detected!');
        if (message.agreement === 'ika') {
            _assert(utils.arrayEqual(this.members, message.members),
                    'Member list mis-match in CLIQUES protocol');
        }
        _assert(message.members.indexOf(this.id) >= 0,
                'Not in members list, must be excluded.');
        _assert(message.members.length === message.intKeys.length,
                'Mis-match intermediate key number for CLIQUES downflow.');
        this.members = message.members;
        this._setKeys(message.intKeys);
    };


    /**
     * Updates local state for group and intermediate keys.
     *
     * @method
     * @param intKeys
     *     Intermediate keys.
     * @private
     */
    ns.CliquesMember.prototype._setKeys = function(intKeys) {
        // New objects for intermediate keys.
        var myPos = this.members.indexOf(this.id);
        this.intKeys = intKeys;
        this.groupKey = ns.deriveGroupKey(
            ns._computeKeyList(this.privKeyList, this.intKeys[myPos]));
    };


    /**
     * Applies scalar multiplication of all private keys with an intermediate
     * key.
     *
     * @param privKeyList {array}
     *     List of private keys.
     * @param intKey
     *     Intermediate key.
     * @returns
     *     Scalar product of keys.
     * @private
     */
    ns._computeKeyList = function(privKeyList, intKey) {
        var result = intKey;
        for (var i in privKeyList) {
            result = jodid25519.dh.computeKey(privKeyList[i], result);
        }
        return result;
    };


    return ns;
});
