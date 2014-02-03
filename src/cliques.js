/**
 * @module cliques
 * 
 * Implementation of group key agreement based on CLIQUES.
 * 
 * Michael Steiner, Gene Tsudik, and Michael Waidner. 2000.
 * "Key Agreement in Dynamic Peer Groups."
 * IEEE Trans. Parallel Distrib. Syst. 11, 8 (August 2000), 769-780.
 * DOI=10.1109/71.877936
 * 
 * This implementation is using the Curve25519 for ECDH mechanisms as a base
 * extended for group key agreement.
 */

"use strict";

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
 * @param keys
 *     List (array) of keys to transmit.
 * @param debugKeys
 *     List (array) of keying debugging strings.
 * @returns {CliquesMessage}
 * @constructor
 */
function CliquesMessage(source, dest, agreement, flow, members, keys, debugKeys) {
    this.source = source || '';
    this.dest = dest || '';
    this.agreement = agreement || '';
    this.flow = flow || '';
    this.members = members || [];
    this.keys = keys || [];
    this.debugKeys = debugKeys || [];
    return this;
}


/**
 * Implementation of group key agreement based on CLIQUES.
 * 
 * This implementation is using the Curve25519 for ECDH mechanisms as a base 
 * extended for group key agreement.
 * 
 * @param id
 *     Member's identifier string.
 * @returns {CliquesMember}
 * @constructor
 */
function CliquesMember(id) {
    /** @member id - Member's identifier string. */
    this.id = id;
    /** @member members - List of all participants. */
    this.members = [];
    /** @member intKeys
     *      List (array) of intermediate keys for all participants. The key for
     *      each participant contains all others' contributions but the
     *      participant's one. */
    this.intKeys = null;
    /** @member privKey - This participant's private key. */
    this.privKey = null;
    /** @member groupKey - Shared secret, the group key. */
    this.groupKey = null;
    // For debugging: Chain of all scalar multiplication keys.
    this._debugIntKeys = null;
    this._debugPrivKeys = null;
    this._debugGroupKey = null;
    
    return this;
}

/**
 * Start the IKA (Initial Key Agreement) procedure for the given members.
 * 
 * @param otherMembers
 *     Iterable of other members for the group (excluding self).
 * @returns {CliquesMessage}
 * @method
 */
CliquesMember.prototype.ika = function(otherMembers) {
    assert(otherMembers.length !== 0, 'No members to add.');
    this.intKeys = null;
    this._debugIntKeys = null;
    if (this.privKey) {
        _clearmem(this.privKey);
        this.privKey = null;
        this._debugPrivKey = null;
    }
    var startMessage = new CliquesMessage(this.id);
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
CliquesMember.prototype.akaJoin = function(newMembers) {
    assert(newMembers.length !== 0, 'No members to add.');
    var allMembers = this.members.concat(newMembers);
    assert(_arrayIsSet(allMembers), 'Duplicates in member list detected!');
    
    // Replace members list.
    this.members = allMembers;
    
    // Renew all keys.
    var retValue = this._renewPrivKey();
    
    // Start of AKA upflow, so we can't be the last member in the chain.
    // Add the new cardinal key.
    this.intKeys.push(retValue.cardinalKey);
    this._debugIntKeys.push(retValue.cardinalDebugKey);
    
    // Pass a message on to the first new member to join.
    var startMessage = new CliquesMessage(this.id);
    startMessage.members = allMembers;
    startMessage.dest = newMembers[0];
    startMessage.agreement = 'aka';
    startMessage.flow = 'upflow';
    startMessage.keys = this.intKeys;
    startMessage.debugKeys = this._debugIntKeys;
    
    return startMessage;
};


/**
 * Start the AKA (Auxiliary Key Agreement) for excluding members.
 * 
 * @param excludeMembers
 *     Iterable of new members to join the group.
 * @returns {CliquesMessage}
 * @method
 */
CliquesMember.prototype.akaExclude = function(excludeMembers) {
    assert(excludeMembers.length !== 0, 'No members to exclude.');
    assert(_arrayIsSubSet(excludeMembers, this.members),
           'Members list to exclude is not a sub-set of previous members!');
    assert(excludeMembers.indexOf(this.id) < 0,
           'Cannot exclude mysefl.');
    
    // Which indices need to be excluded.
    var indicesToExclude = [];
    
    for (var i = 0; i < excludeMembers.length; i++) {
        indicesToExclude.push(this.members.indexOf(excludeMembers[i]));
    }
    indicesToExclude.sort();
    indicesToExclude.reverse();
        
    // Kick 'em.
    for (var i = 0; i < indicesToExclude.length; i++) {
        this.members.remove(indicesToExclude[i]);
        this.intKeys.remove(indicesToExclude[i]);
        this._debugIntKeys.remove(indicesToExclude[i]);
    }
    
    // Renew all keys.
    var retValue = this._renewPrivKey();
    
    // Discard old and make new group key.
    if (this.groupKey) {
        _clearmem(this.groupKey);
        this.groupKey = null;
    }
    this.groupKey = retValue.cardinal;
    this._debugGroupKey = retValue.cardinalDebugKey;
    
    // Pass broadcast message on to all members.
    var broadcastMessage = new CliquesMessage(this.id);
    broadcastMessage.members = this.members;
    broadcastMessage.agreement = 'aka';
    broadcastMessage.flow = 'downflow';
    broadcastMessage.keys = this.intKeys;
    broadcastMessage.debugKeys = this._debugIntKeys;
    
    return broadcastMessage;
};


/**
 * Start the AKA (Auxiliary Key Agreement) for refreshing the own private key.
 * 
 * @returns {CliquesMessage}
 * @method
 */
CliquesMember.prototype.akaRefresh = function() {
    // Renew all keys.
    var retValue = this._renewPrivKey();
    
    // Discard old and make new group key.
    if (this.groupKey) {
        _clearmem(this.groupKey);
        this.groupKey = null;
    }
    this.groupKey = retValue.cardinal;
    this._debugGroupKey = retValue.cardinalDebugKey;
    
    // Pass broadcast message on to all members.
    var broadcastMessage = new CliquesMessage(this.id);
    broadcastMessage.members = this.members;
    broadcastMessage.agreement = 'aka';
    broadcastMessage.flow = 'downflow';
    broadcastMessage.keys = this.intKeys;
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
CliquesMember.prototype.upflow = function(message) {
    assert(_arrayIsSet(message.members), 'Duplicates in member list detected!');
    
    this.members = message.members;
    this.intKeys = message.keys;
    this._debugIntKeys = message.debugKeys;
    if (this.intKeys.length === 0) {
        // We're the first, so let's initialise it.
        this.intKeys = [null];
        this._debugIntKeys = [null];
    }
    
    // Renew all keys.
    var result = this._renewPrivKey();
    var myPos = this.members.indexOf(this.id);
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
    message.keys = this.intKeys;
    message.debugKeys = this._debugIntKeys;
    return message;
};


/**
 * .Renew the private key, update the set of intermediate keys and return
 *  the new cardinal key.
 * 
 * @returns - Cardinal key and cardinal debug key in an object.
 * @private
 * @method
 */
CliquesMember.prototype._renewPrivKey = function() {
    var myPos = this.members.indexOf(this.id);
    if (this.privKey) {
        // Patch our old private key into intermediate keys.
        this.intKeys[myPos] = _scalarMultiply(this.privKey, this.intKeys[myPos]);
        this._debugIntKeys[myPos] = _scalarMultiplyDebug(this._debugPrivKey,
                                                         this._debugIntKeys[myPos]);
        // Discard old private key.
        _clearmem(this.privKey);
        this.privKey = null;
    }
    
    // Make a new private key.
    this.privKey = _newKey256();
    if (this._debugPrivKey) {
        this._debugPrivKey = this._debugPrivKey + "'";
    } else {
        this._debugPrivKey = this.id;
    }
    
    // Update intermediate keys.
    for (var i = 0; i < this.intKeys.length; i++) {
        if (i !== myPos) {
            this.intKeys[i] = _scalarMultiply(this.privKey, this.intKeys[i]);
            this._debugIntKeys[i] = _scalarMultiplyDebug(this._debugPrivKey,
                                                         this._debugIntKeys[i]);
        }
    }
    
    // New cardinal is "own" intermediate scalar multiplied with our private.
    return {
        'cardinalKey': _scalarMultiply(this.privKey, this.intKeys[myPos]),
        'cardinalDebugKey' : _scalarMultiplyDebug(this._debugPrivKey,
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
CliquesMember.prototype.downflow = function(message) {
    assert(_arrayIsSet(message.members), 'Duplicates in member list detected!');
    if (message.agreement === 'ika') {
        assert(this.members.toString() === message.members.toString(),
               'Member list mis-match in protocol');
    } else {
        assert(_arrayIsSubSet(this.members, message.members),
               'Members list in message not a super-set of previous members!');
    }
    assert(message.members.indexOf(this.id) >= 0,
           'Not in members list, must be excluded.');
    
    this.members = message.members;
    this._setKeys(message.keys, message.debugKeys);
};


/**
 * Updates local state for group and intermediate keys.
 * 
 * @param intKeys - Intermediate keys.
 * @param debugKeys - Debug "key" sequences.
 * @private
 * @method
 */
CliquesMember.prototype._setKeys = function(intKeys, debugKeys) {
    if ((this.intKeys) && (this.groupKey)) {
        _clearmem(this.groupKey);
        this.groupKey = null;
        this._debugGroupKey = null;
    }
    // New objects for intermediate keys.
    var myPos = this.members.indexOf(this.id);
    this.intKeys = intKeys.map(_arrayCopy);
    this._debugIntKeys = debugKeys.map(_arrayCopy);
    this.groupKey = _scalarMultiply(this.privKey,
                                    this.intKeys[myPos]);
    this._debugGroupKey = _scalarMultiplyDebug(this._debugPrivKey,
                                               this._debugIntKeys[myPos]);
};


/**
 * Perform scalar product of a private key with an intermediate key..
 * 
 * In case intKey is undefined, privKey will be multiplied with the curve's
 * base point. 
 *  
 * @param privKey - Private key.
 * @param intKey - Intermediate key.
 * @returns - Scalar product of keys.
 * @private
 */
function _scalarMultiply(privKey, intKey) {
    if (intKey) {
        return curve25519(privKey, intKey);
    } else {
        return curve25519(privKey);
    }
}


/**
 * Debug version of `_scalarMultiply()`.
 * 
 * In case intKey is undefined, privKey will be multiplied with the curve's
 * base point. 
 *  
 * @param privKey - Private key.
 * @param intKey - Intermediate key.
 * @returns - Scalar product of keys.
 * @private
 */
function _scalarMultiplyDebug(privKey, intKey) {
    if (intKey) {
        return privKey + '*' + intKey;
    } else {
        return privKey + '*G';
    }
}


/**
 * Checks for unique occurrence of all elements within the array.
 * 
 * Note: Array members must be directly comparable for equality
 * (g. g. numbers or strings).
 * 
 * @param theArray - Array under scrutiny.
 * @returns - True for uniqueness.
 * @private
 */
function _arrayIsSet(theArray) {
    // Until ES6 is down everywhere to offer the Set() class, we need to work
    // around it.
    var mockSet = {};
    var item;
    for (var i = 0; i < theArray.length; i++) {
        item = theArray[i];
        if (item in mockSet) {
            return false;
        } else {
            mockSet[item] = true;
        }
    }
    return true;
}


/**
 * Checks whether one array's elements are a subset of another.
 * 
 * Note: Array members must be directly comparable for equality
 * (g. g. numbers or strings).
 * 
 * @param subset - Array to be checked for being a subset.
 * @param superset - Array to be checked for being a superset.
 * @returns - True for the first being a subset of the second.
 * @private
 */
function _arrayIsSubSet(subset, superset) {
    // Until ES6 is down everywhere to offer the Set() class, we need to work
    // around it.
    var mockSet = {};
    var item;
    for (var i = 0; i < superset.length; i++) {
        item = superset[i];
        if (item in mockSet) {
            return false;
        } else {
            mockSet[item] = true;
        }
    }
    for (var i = 0; i < subset.length; i++) {
        if (!(subset[i] in mockSet)) {
            return false;
        }
    }
    return true;
}


/**
 * Dumb array copy helper.
 * 
 * @param item - The item for iterator.
 * @returns The item itself.
 * @private
 */
function _arrayCopy(item) {
    return item;
}


/**
 * Clears the memory of a secret key array.
 * 
 * @param key - The key to clear.
 * @private
 */
function _clearmem(key) {
    for (var i = 0; i < key.length; i++) {
        key[i] = 0;
    }
}


/**
 * Generates a new 256 bit random key, and converts it into a format that
 * the Curve25519 implementatino understands.
 * 
 * @returns 16 bit word array of the key.
 * @private
 */
function _newKey256() {
    // TODO: Replace with Mega's implementation of rand(n)
    // https://github.com/meganz/webclient/blob/master/js/keygen.js#L21
    return c255lhexdecode(sjcl.codec.hex.fromBits(sjcl.random.randomWords(8, 6)));
}
