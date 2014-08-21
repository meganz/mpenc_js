/**
 * @fileOverview
 * Implementation of group key agreement based on CLIQUES.
 */

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "jodid25519"
], function(assert, utils, jodid25519) {
    "use strict";

    /**
     * @exports mpenc/greet/cliques
     * Implementation of group key agreement based on CLIQUES.
     *
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

    /*
     * Created: 20 Jan 2014 Guy K. Kloss <gk@mega.co.nz>
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
     * Carries message content for the CLIQUES protocol.
     *
     * @param source
     *     Message originator (from).
     * @param dest
     *     Message destination (to).
     * @param agreement
     *     Type of key agreement. "ika" or "aka".
     * @param flow
     *     Direction of message flow. "upflow" or "downflow".
     * @param members
     *     List (array) of all participating members.
     * @param intKeys
     *     List (array) of intermediate keys to transmit.
     * @param debugKeys
     *     List (array) of keying debugging strings.
     * @returns {CliquesMessage}
     * @constructor
     *
     * @property source
     *     Message originator (from).
     * @property dest
     *     Message destination (to).
     * @property agreement
     *     Type of key agreement. "ika" or "aka".
     * @property flow
     *     Direction of message flow. "upflow" or "downflow".
     * @property members
     *     List (array) of all participating members.
     * @property intKeys
     *     List (array) of intermediate keys to transmit.
     * @property debugKeys
     *     List (array) of keying debugging strings.
     */
    ns.CliquesMessage = function(source, dest, agreement, flow, members,
                                 intKeys, debugKeys) {
        this.source = source || '';
        this.dest = dest || '';
        this.agreement = agreement || '';
        this.flow = flow || '';
        this.members = members || [];
        this.intKeys = intKeys || [];
        this.debugKeys = debugKeys || [];
        return this;
    };


    /**
     * Implementation of group key agreement based on CLIQUES.
     *
     * This implementation is using the Curve25519 for ECDH mechanisms as a base
     * extended for group key agreement.
     *
     * @constructor
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
     * @property privKeyId
     *     The ID of the private key (incrementing integer, starting from 0).
     * @property keyTimestamp
     *     Time stamp indicator when `privKey` was created/refreshed.
     *     Some monotonously increasing counter.
     * @property groupKey
     *     Shared secret, the group key.
     */
    ns.CliquesMember = function(id) {
        this.id = id;
        this.members = [];
        this.intKeys = null;
        this.privKey = null;
        this.privKeyId = 0;
        this.keyTimestamp = null;
        this.groupKey = null;
        // For debugging: Chain of all scalar multiplication keys.
        this._debugIntKeys = null;
        this._debugGroupKey = null;

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
        this._debugIntKeys = null;
        this.privKey = null;
        this._debugPrivKey = null;
        var startMessage = new ns.CliquesMessage(this.id);
        startMessage.members = [this.id].concat(otherMembers);
        startMessage.agreement = 'ika';
        startMessage.flow = 'upflow';
        return this.upflow(startMessage);
    };


    /**
     * Start the IKA (Initial Key Agreement) for a full/complete refresh of
     * all keys.
     *
     * @returns {CliquesMessage}
     * @method
     */
    ns.CliquesMember.prototype.ikaFullRefresh = function() {
        // Start with the other members.
        var otherMembers = utils.clone(this.members);
        var myPos = otherMembers.indexOf(this.id);
        otherMembers.splice(myPos, 1);
        return this.ika(otherMembers);
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
        var retValue = this._renewPrivKey();

        // Start of AKA upflow, so we can't be the last member in the chain.
        // Add the new cardinal key.
        this.intKeys.push(retValue.cardinalKey);
        this._debugIntKeys.push(retValue.cardinalDebugKey);

        // Pass a message on to the first new member to join.
        var startMessage = new ns.CliquesMessage(this.id);
        startMessage.members = allMembers;
        startMessage.dest = newMembers[0];
        startMessage.agreement = 'aka';
        startMessage.flow = 'upflow';
        startMessage.intKeys = this.intKeys;
        startMessage.debugKeys = this._debugIntKeys;

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
            this._debugIntKeys.splice(index, 1);
        }

        // Renew all keys.
        var retValue = this._renewPrivKey();

        // Discard old and make new group key.
        this.groupKey = utils.sha256(retValue.cardinalKey);
        this._debugGroupKey = retValue.cardinalDebugKey;

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.CliquesMessage(this.id);
        broadcastMessage.members = this.members;
        broadcastMessage.agreement = 'aka';
        broadcastMessage.flow = 'downflow';
        broadcastMessage.intKeys = this.intKeys;
        broadcastMessage.debugKeys = this._debugIntKeys;

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
        _assert(this.privKey !== null, 'Not participating.');

        // Kick myself out.
        var myPos = this.members.indexOf(this.id);
        if (myPos >= 0) {
            this.members.splice(myPos, 1);
            this.intKeys = [];
            this._debugIntKeys = [];
            this.privKey = null;
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
        var retValue = this._renewPrivKey();

        // Discard old and make new group key.
        this.groupKey = null;
        this.groupKey = utils.sha256(retValue.cardinalKey);
        this._debugGroupKey = retValue.cardinalDebugKey;

        // Pass broadcast message on to all members.
        var broadcastMessage = new ns.CliquesMessage(this.id);
        broadcastMessage.members = this.members;
        broadcastMessage.agreement = 'aka';
        broadcastMessage.flow = 'downflow';
        broadcastMessage.intKeys = this.intKeys;
        broadcastMessage.debugKeys = this._debugIntKeys;

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
        this._debugIntKeys = message.debugKeys;
        if (this.intKeys.length === 0) {
            // We're the first, so let's initialise it.
            this.intKeys = [null];
            this._debugIntKeys = [null];
        }

        // To not confuse _renewPrivKey() in full refresh situation.
        if (message.agreement === 'ika') {
            this.privKey = null;
            this._debugPrivKey = null;
        }

        // Renew all keys.
        var result = this._renewPrivKey();
        var myPos = this.members.indexOf(this.id);

        // Clone message.
        message = utils.clone(message);
        if (myPos === this.members.length - 1) {
            // I'm the last in the chain:
            // Cardinal is secret key.
            this.groupKey = utils.sha256(result.cardinalKey);
            this._debugGroupKey = result.cardinalDebugKey;
            this._setKeys(this.intKeys, this._debugIntKeys);
            // Broadcast all intermediate keys.
            message.source = this.id;
            message.dest = '';
            message.flow = 'downflow';
        } else {
            // Add the new cardinal key.
            this.intKeys.push(result.cardinalKey);
            this._debugIntKeys.push(result.cardinalDebugKey);
            // Pass a message on to the next in line.
            message.source = this.id;
            message.dest = this.members[myPos + 1];
        }
        message.intKeys = this.intKeys;
        message.debugKeys = this._debugIntKeys;
        return message;
    };


    /**
     * Renew the private key, update the set of intermediate keys and return
     * the new cardinal key.
     *
     * @returns
     *     Cardinal key and cardinal debug key in an object.
     * @method
     * @private
     */
    ns.CliquesMember.prototype._renewPrivKey = function() {
        var myPos = this.members.indexOf(this.id);
        if (this.privKey) {
            // Patch our old private key into intermediate keys.
            this.intKeys[myPos] = jodid25519.dh.computeKey(this.privKey,
                                                           this.intKeys[myPos]);
            this._debugIntKeys[myPos] = ns._computeKeyDebug(this._debugPrivKey,
                                                            this._debugIntKeys[myPos]);
            this.privKey = null;
        }

        // Make a new private key.
        this.privKey = jodid25519.dh.generateKey();
        this.privKeyId++;
        this.keyTimestamp = Math.round(Date.now() / 1000);
        if (this._debugPrivKey) {
            this._debugPrivKey = this._debugPrivKey + "'";
        } else {
            this._debugPrivKey = this.id;
        }

        // Update intermediate keys.
        for (var i = 0; i < this.intKeys.length; i++) {
            if (i !== myPos) {
                this.intKeys[i] = jodid25519.dh.computeKey(this.privKey,
                                                           this.intKeys[i]);
                this._debugIntKeys[i] = ns._computeKeyDebug(this._debugPrivKey,
                                                            this._debugIntKeys[i]);
            }
        }

        // New cardinal is "own" intermediate scalar multiplied with our private.
        var cardinalKey = jodid25519.dh.computeKey(this.privKey,
                                                   this.intKeys[myPos]);
        return {
            cardinalKey: '' + cardinalKey,
            cardinalDebugKey: ns._computeKeyDebug(this._debugPrivKey,
                                                  this._debugIntKeys[myPos])
        };
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
        this._setKeys(message.intKeys, message.debugKeys);
    };


    /**
     * Updates local state for group and intermediate keys.
     *
     * @method
     * @param intKeys
     *     Intermediate keys.
     * @param debugKeys
     *     Debug "key" sequences.
     * @private
     */
    ns.CliquesMember.prototype._setKeys = function(intKeys, debugKeys) {
        this.groupKey = null;
        this._debugGroupKey = null;

        // New objects for intermediate keys.
        var myPos = this.members.indexOf(this.id);
        this.intKeys = intKeys;
        this._debugIntKeys = debugKeys;
        this.groupKey = utils.sha256(jodid25519.dh.computeKey(this.privKey,
                                                              this.intKeys[myPos]));
        this._debugGroupKey = ns._computeKeyDebug(this._debugPrivKey,
                                                  this._debugIntKeys[myPos]);
    };


    /**
     * Debug version of `jodid25519.dh.computeKey()`.
     *
     * In case intKey is undefined, privKey will be multiplied with the curve's
     * base point.
     *
     * @param privKey
     *     Private key.
     * @param intKey
     *     Intermediate key.
     * @returns
     *     Scalar product of keys.
     * @private
     */
    ns._computeKeyDebug = function(privKey, intKey) {
        if (intKey) {
            return privKey + '*' + intKey;
        } else {
            return privKey + '*G';
        }
    };

    return ns;
});
