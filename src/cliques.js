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
        this._debubPrivKey = null;
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
    assert(len(otherMembers) !== 0, 'No members to add.');
    var allMembers = this.members.concat(newMembers);
    assert(_arrayIsSet(allMembers), 'Duplicates in member list detected!');
    
    // Replace members list.
    this.members = allMembers;
    
    // Renew all keys.
    var retValue = this._renewPrivKey();
    var cardinal = retValue.cardinal;
    var cardinalDebugKey = retValue.cardinalDebugKey;
    
    // TODO:
    // * make this._renewPrivKey()
    // * continue from here down
    
    // Start of AKA upflow, so we can't be the last member in the chain.
    // Add the new cardinal key.
    this.intKeys.push(cardinal);
    this._debugIntKeys.push(cardinalDebugKey);
    
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
    if (!this.intKeys) {
        // We're the first, so let's initialise it.
        this.intKeys = [null];
        this._debugIntKeys = [null];
    }

    // Renew all keys.
    
    // Make a new secret, and convert that to a format the Curve25519
    // implementation understands.
    this.privKey = _newKey256();
    var keys = message.keys.map(_arrayCopy);
    var debugKeys = message.debugKeys.map(_arrayCopy);
    if (keys.length === 0) {
        // We're the first, so let's initialise it.
        keys = [null];
        debugKeys = [null];
    }
    
    // Update intermediate keys.
    for (var i = 0; i < keys.length - 1; i++) {
        keys[i] = _scalarMultiply(this.privKey, keys[i]);
        debugKeys[i] = _scalarMultiplyDebug(this.id, debugKeys[i]);
    }
    
    // New cardinal is last cardinal scalar multiplied with our private.
    var lastIndex = keys.length - 1;
    var cardinalKey = _scalarMultiply(this.privKey, keys[lastIndex]);
    var cardinalDebugKey = _scalarMultiplyDebug(this.id, debugKeys[lastIndex]);
    if (this.myPos === this.members.length - 1) {
        // I'm the last in the chain.
        // Cardinal is secret key, and broadcast all intermediate keys.
        this.groupKey = cardinalKey;
        this._debugGroupKey = cardinalDebugKey;
        this._setKeys(keys, debugKeys);
        message.source = this.id;
        message.dest = '';
        message.flow = 'downflow';
    } else {
        // Add the new cardinal key and pass a message on to the next in line.
        keys.push(cardinalKey);
        debugKeys.push(cardinalDebugKey);
        message.source = this.id;
        message.dest = this.members[this.myPos + 1];
    }
    message.keys = keys;
    message.debugKeys = debugKeys;
    return message;
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
    assert(this.members.toString() === message.members.toString(),
           'Member list mis-match in protocol');
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
        if (intKeys.toString() === this.intKeys.toString()) {
            // We're OK already.
            return
        } else {
            _clearmem(this.groupKey);
        }
    }
    // New objects for intermediate keys.
    this.myPos = this.members.indexOf(this.id);
    this.intKeys = intKeys.map(_arrayCopy);
    this._debugIntKeys = debugKeys.map(_arrayCopy);
    this.groupKey = _scalarMultiply(this.privKey,
                                    this.intKeys[this.myPos]);
    this._debugGroupKey = _scalarMultiplyDebug(this.id,
                                               this._debugIntKeys[this.myPos]);
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
