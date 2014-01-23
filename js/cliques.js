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
 * @param msgType
 *     Message type.
 * @param members
 *     List (array) of all participating members.
 * @param keys
 *     List (array) of keys to transmit.
 * @param debugKeys
 *     List (array) of keying debugging strings.
 * @returns {CliquesMessage}
 * @constructor
 */
function CliquesMessage(source, dest, msgType, members, keys, debugKeys) {
    this.source = source || '';
    this.dest = dest || '';
    this.msgType = msgType || 'ika_upflow';
    this.members = members || [];
    this.keys = keys || [];
    this.debugKeys = debugKeys || [];

//    // Default options, which can be overridden through `opts`.
//    var defaults = {
//        /** @member source - Message originator (from). */
//        source: '',
//        /** @member dest - Message destination (to). */
//        dest: '',
//        /** @member msgType - Message type. */
//        msgType: 'ika_upflow',
//        /** @member members - List (array) of all participating members. */
//        members: [],
//        /** @member keys - List (array) of keys to transmit. */
//        keys: [],
//        /** @member debugKeys - List (array) of keying debugging strings. */
//        debugKeys: []
//    };
//    this.options = $.extend(true, {}, defaults, opts);
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
    /** @member myPos - My position in the members list. */
    this.myPos = null;
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
    this._debugGroupKey = null;
    this._debugIntKeys = null;
    
    return this;
}

/**
 * Start the IKA (Initial Key Agreement) procedure for the given members.
 * 
 * @param otherMembers
 *     Iterable of other members for the group (excluding self).
 * @method
 */
CliquesMember.prototype.startIka = function(otherMembers) {
    var startMessage = new CliquesMessage(this.id);
    startMessage.members = [this.id].concat(otherMembers);
    return this.ikaUpflow(startMessage);
};


/**
 * IKA upflow phase message receive.
 * 
 * @param message
 *     Received upflow message. See {@link CliquesMessage}.
 * @returns - {CliquesMember}
 * @method
 */
CliquesMember.prototype.ikaUpflow = function(message) {
    this.members = message.members;
    this.myPos = this.members.indexOf(this.id);
    
    // FIXME: Use curve255.js
    // curve25519() is what we need:
    // var my_public_key = curve25519(my_secret);
    // var shared_secret = curve25519(my_secret, public_key);
    
    // Look at notes on https://github.com/rev22/curve255js from README.md:
    // Private and public keys are represented by arrays of 16-bit values,
    // starting from the least significant ones:
    // key = arr[0] + arr[1] × 2^16 + arr[2] × 2^32 + ... + arr[15] × 2^(16*15)

    // Need to modify this to use string or byte array? Or just go with this ...?
    
    // Keys:
    // - asmcrypto.js: binary strings or Uint8Array objects or ArrayBuffer objects.
    // - sjcl: generates array of 32 bit words with sjcl.random.randomWords(nwords, paranoia)
    //   https://github.com/bitwiseshiftleft/sjcl/blob/master/core/random.js
    
    
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
        keys[i] = _scalarMultiply(this.privKey, keys[i]); // TODO: Fix for real.
        debugKeys[i] = _scalarMultiplyDebug(this.id, debugKeys[i]);
    }
    
    // New cardinal is last cardinal scalar multiplied with our private.
    var lastIndex = keys.length - 1;
    var cardinalKey = _scalarMultiply(this.privKey, keys[lastIndex]); // TODO: Fix for real.
    var cardinalDebugKey = _scalarMultiplyDebug(this.id, debugKeys[lastIndex]);
    if (this.myPos === this.members.length - 1) {
        // I'm the last in the chain.
        // Cardinal is secret key, and broadcast all intermediate keys.
        /**
         * @param message
         */
        /**
         * @param message
         */
        this.groupKey = cardinalKey;
        this._debugGroupKey = cardinalDebugKey;
        this._setKeys(keys, debugKeys);
        message.source = this.id;
        message.dest = '';
        message.msgType = 'ika_downflow';
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
CliquesMember.prototype.ikaDownflow = function(message) {
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
            // Safely wipe the memory of the previous secret.
            // TODO: Look at a mutable data structure here.
            // (Note: Strings are immutable.)
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
 * Dumb array copy helper.
 * @param item - The item for iterator.
 * @returns The item itself.
 * @private
 */
function _arrayCopy(item) {
    return item;
}


/**
 * Generates a new 256 bit random key, and converts it into a format that
 * the Curve25519 implementatino understands.
 * @returns 16 bit word array of the key.
 * @private
 */
function _newKey256() {
    return c255lhexdecode(sjcl.codec.hex.fromBits(sjcl.random.randomWords(8, 6)));
}
