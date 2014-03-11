/**
 * @fileOverview
 * Implementation of group key agreement based on CLIQUES.
 */

(function() {
    "use strict";

    /** 
     * @namespace
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
    mpenc.cliques = {};
    
    var _assert = mpenc.assert.assert;
    
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
    mpenc.cliques.CliquesMessage = function(source, dest, agreement, flow, members,
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
     * @property keyTimestamp
     *     Time stamp indicator when `privKey` was created/refreshed.
     *     Some monotonously increasing counter.
     * @property groupKey
     *     Shared secret, the group key.
     */
    mpenc.cliques.CliquesMember = function(id) {
        this.id = id;
        this.members = [];
        this.intKeys = null;
        this.privKey = null;
        this.keyTimestamp = null;
        this.groupKey = null;
        // For debugging: Chain of all scalar multiplication keys.
        this._debugIntKeys = null;
        this._debugPrivKeys = null;
        this._debugGroupKey = null;
        
        return this;
    };
    
    /**
     * Start the IKA (Initial Key Agreement) procedure for the given members.
     * 
     * @param otherMembers
     *     Iterable of other members for the group (excluding self).
     * @returns {CliquesMessage}
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.ika = function(otherMembers) {
        _assert(otherMembers.length !== 0, 'No members to add.');
        this.intKeys = null;
        this._debugIntKeys = null;
        if (this.privKey) {
            mpenc.utils._clearmem(this.privKey);
            this.privKey = null;
            this._debugPrivKey = null;
        }
        var startMessage = new mpenc.cliques.CliquesMessage(this.id);
        startMessage.members = [this.id].concat(otherMembers);
        startMessage.agreement = 'ika';
        startMessage.flow = 'upflow';
        return this.upflow(startMessage);
    };
    
    
    /**
     * Start the AKA (Auxiliary Key Agreement) for joining new members.
     * 
     * @param newMembers
     *     Iterable of new members to join the group.
     * @returns {CliquesMessage}
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.akaJoin = function(newMembers) {
        _assert(newMembers.length !== 0, 'No members to add.');
        var allMembers = this.members.concat(newMembers);
        _assert(mpenc.utils._noDuplicatesInList(allMembers),
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
        var startMessage = new mpenc.cliques.CliquesMessage(this.id);
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
     * @param excludeMembers
     *     Iterable of members to exclude from the group.
     * @returns {CliquesMessage}
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.akaExclude = function(excludeMembers) {
        _assert(excludeMembers.length !== 0, 'No members to exclude.');
        _assert(mpenc.utils._arrayIsSubSet(excludeMembers, this.members),
                'Members list to exclude is not a sub-set of previous members!');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');
        
        // Kick 'em.
        for (var i = 0; i < excludeMembers.length; i++) {
            var index = this.members.indexOf(excludeMembers[i]);
            this.members[index] = null;
            this.intKeys[index] = null;
            this._debugIntKeys[index] = null;
        }
        
        // Renew all keys.
        var retValue = this._renewPrivKey();
        
        // Discard old and make new group key.
        if (this.groupKey) {
            mpenc.utils._clearmem(this.groupKey);
            this.groupKey = null;
        }
        this.groupKey = retValue.cardinal;
        this._debugGroupKey = retValue.cardinalDebugKey;
        
        // Pass broadcast message on to all members.
        var broadcastMessage = new mpenc.cliques.CliquesMessage(this.id);
        broadcastMessage.members = this.members;
        broadcastMessage.agreement = 'aka';
        broadcastMessage.flow = 'downflow';
        broadcastMessage.intKeys = this.intKeys;
        broadcastMessage.debugKeys = this._debugIntKeys;
        
        return broadcastMessage;
    };
    
    
    /**
     * Start the AKA (Auxiliary Key Agreement) for refreshing the own private key.
     * 
     * @returns {CliquesMessage}
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.akaRefresh = function() {
        // Renew all keys.
        var retValue = this._renewPrivKey();
        
        // Discard old and make new group key.
        if (this.groupKey) {
            mpenc.utils._clearmem(this.groupKey);
            this.groupKey = null;
        }
        this.groupKey = retValue.cardinal;
        this._debugGroupKey = retValue.cardinalDebugKey;
        
        // Pass broadcast message on to all members.
        var broadcastMessage = new mpenc.cliques.CliquesMessage(this.id);
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
     * @param message
     *     Received upflow message. See {@link CliquesMessage}.
     * @returns {CliquesMessage}
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.upflow = function(message) {
        _assert(mpenc.utils._noDuplicatesInList(message.members),
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
        
        // Renew all keys.
        var result = this._renewPrivKey();
        var myPos = this.members.indexOf(this.id);
        
        // Clone message.
        message = mpenc.utils.clone(message);
        if (myPos === this.members.length - 1) {
            // I'm the last in the chain:
            // Cardinal is secret key.
            this.groupKey = result.cardinalKey;
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
     * @private
     * @method
     */
    mpenc.cliques.CliquesMember.prototype._renewPrivKey = function() {
        var myPos = this.members.indexOf(this.id);
        if (this.privKey) {
            // Patch our old private key into intermediate keys.
            this.intKeys[myPos] = mpenc.cliques._scalarMultiply(this.privKey,
                                                                this.intKeys[myPos]);
            this._debugIntKeys[myPos] = mpenc.cliques._scalarMultiplyDebug(this._debugPrivKey,
                                                                           this._debugIntKeys[myPos]);
            // Discard old private key.
            mpenc.utils._clearmem(this.privKey);
            this.privKey = null;
        }
        
        // Make a new private key.
        this.privKey = mpenc.utils._newKey16(256);
        this.keyTimestamp = Math.round(Date.now() / 1000);
        if (this._debugPrivKey) {
            this._debugPrivKey = this._debugPrivKey + "'";
        } else {
            this._debugPrivKey = this.id;
        }
        
        // Update intermediate keys.
        for (var i = 0; i < this.intKeys.length; i++) {
            if (i !== myPos) {
                this.intKeys[i] = mpenc.cliques._scalarMultiply(this.privKey,
                                                                this.intKeys[i]);
                this._debugIntKeys[i] = mpenc.cliques._scalarMultiplyDebug(this._debugPrivKey,
                                                                           this._debugIntKeys[i]);
            }
        }
        
        // New cardinal is "own" intermediate scalar multiplied with our private.
        return {
            'cardinalKey': mpenc.cliques._scalarMultiply(this.privKey, this.intKeys[myPos]),
            'cardinalDebugKey': mpenc.cliques._scalarMultiplyDebug(this._debugPrivKey,
                                                                   this._debugIntKeys[myPos])
        };
    };
    
    /**
     * IKA downflow phase broadcast message receive.
     * 
     * @param message
     *     Received downflow broadcast message.
     * @method
     */
    mpenc.cliques.CliquesMember.prototype.downflow = function(message) {
        _assert(mpenc.utils._noDuplicatesInList(message.members),
                'Duplicates in member list detected!');
        if (message.agreement === 'ika') {
            _assert(mpenc.utils.arrayEqual(this.members, message.members),
                    'Member list mis-match in CLIQUES protocol');
        }
        _assert(message.members.indexOf(this.id) >= 0,
                'Not in members list, must be excluded.');
        
        this.members = message.members;
        this._setKeys(message.intKeys, message.debugKeys);
    };
    
    
    /**
     * Updates local state for group and intermediate keys.
     * 
     * @param intKeys
     *     Intermediate keys.
     * @param debugKeys
     *     Debug "key" sequences.
     * @private
     * @method
     */
    mpenc.cliques.CliquesMember.prototype._setKeys = function(intKeys, debugKeys) {
        if ((this.intKeys) && (this.groupKey)) {
            mpenc.utils._clearmem(this.groupKey);
            this.groupKey = null;
            this._debugGroupKey = null;
        }
        // New objects for intermediate keys.
        var myPos = this.members.indexOf(this.id);
        this.intKeys = mpenc.utils.clone(intKeys);
        this._debugIntKeys = mpenc.utils.clone(debugKeys);
        this.groupKey = mpenc.cliques._scalarMultiply(this.privKey,
                                                      this.intKeys[myPos]);
        this._debugGroupKey = mpenc.cliques._scalarMultiplyDebug(this._debugPrivKey,
                                                                 this._debugIntKeys[myPos]);
    };
    
    
    /**
     * Perform scalar product of a private key with an intermediate key..
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
    mpenc.cliques._scalarMultiply = function(privKey, intKey) {
        if (intKey) {
            return curve25519(privKey, intKey);
        } else {
            return curve25519(privKey);
        }
    };
    
    
    /**
     * Debug version of `_scalarMultiply()`.
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
    mpenc.cliques._scalarMultiplyDebug = function(privKey, intKey) {
        if (intKey) {
            return privKey + '*' + intKey;
        } else {
            return privKey + '*G';
        }
    };
})();
