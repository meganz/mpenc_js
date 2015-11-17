/*
 * Created: 2 Mar 2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "mpenc/greet/cliques",
    "mpenc/greet/ske",
    "mpenc/codec",
    "promise-polyfill",
    "megalogger",
], function(assert, async, struct, utils, cliques, ske, codec, Promise, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/greet/greet
     * @private
     * @description
     * <p>Implementation of a greet (key agreement) protocol wrapper.</p>
     *
     * <p>
     * This protocol handler manages the message flow for user authentication,
     * authenticated signature key exchange, and group key agreement.</p>
     *
     * <p>
     * This implementation is using the an authenticated signature key exchange that
     * also provides participant authentication as well as a CLIQUES-based group
     * key agreement.</p>
     */
    var ns = {};

    var _assert = assert.assert;
    var _T = codec.TLV_TYPE;
    var ImmutableSet = struct.ImmutableSet;

    var logger = MegaLogger.getLogger('greeter', undefined, 'greet');

    var _logIgnored = function(id, pId, message) {
        logger.info(id + ": ignored " + btoa(pId) + "; " + message);
    };

    // Message type bit mapping
    ns._AUX_BIT = 0;
    ns._DOWN_BIT = 1;
    ns._GKA_BIT = 2;
    ns._SKE_BIT = 3;
    ns._OP_BITS = 4;
    ns._INIT_BIT = 7;
    ns._OPERATION = { DATA: 0x00,
                      START: 0x01,
                      INCLUDE: 0x02,
                      EXCLUDE: 0x03,
                      REFRESH: 0x04,
                      QUIT: 0x05 };
    ns._OPERATION_MASK = 0x07 << ns._OP_BITS;
    // Add reverse mapping to string representation.
    ns.OPERATION_MAPPING = {};
    for (var propName in ns._OPERATION) {
        ns.OPERATION_MAPPING[ns._OPERATION[propName]] = propName;
    }


    /**
     * "Enumeration" message types.
     *
     * @property INIT_INITIATOR_UP {string}
     *     Initiator initial upflow.
     * @property INIT_PARTICIPANT_UP {string}
     *     Participant initial upflow message.
     * @property INIT_PARTICIPANT_DOWN {string}
     *     Participant initial downflow.
     * @property INIT_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant initial subsequent downflow.
     * @property INCLUDE_AUX_INITIATOR_UP {string}
     *     Initiator aux include upflow.
     * @property INCLUDE_AUX_PARTICIPANT_UP {string}
     *     Participant aux include upflow.
     * @property INCLUDE_AUX_PARTICIPANT_DOWN {string}
     *     Participant aux include downflow.
     * @property INCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant aux include subsequent downflow.
     * @property EXCLUDE_AUX_INITIATOR_DOWN {string}
     *     Initiator aux exclude downflow.
     * @property EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant aux exclude subsequent.
     * @property REFRESH_AUX_INITIATOR_DOWN {string}
     *     Initiator aux refresh downflow.
     * @property QUIT_DOWN {string}
     *     Indicating departure. (Must be followed by an exclude sequence.)
     */
    ns.GREET_TYPE = {
        // Initial start sequence.
        INIT_INITIATOR_UP:                     '\u0000\u009c', // 0b10011100
        INIT_PARTICIPANT_UP:                   '\u0000\u001c', // 0b00011100
        INIT_PARTICIPANT_DOWN:                 '\u0000\u001e', // 0b00011110
        INIT_PARTICIPANT_CONFIRM_DOWN:         '\u0000\u001a', // 0b00011010
        // Include sequence.
        INCLUDE_AUX_INITIATOR_UP:              '\u0000\u00ad', // 0b10101101
        INCLUDE_AUX_PARTICIPANT_UP:            '\u0000\u002d', // 0b00101101
        INCLUDE_AUX_PARTICIPANT_DOWN:          '\u0000\u002f', // 0b00101111
        INCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN:  '\u0000\u002b', // 0b00101011
        // Exclude sequence.
        EXCLUDE_AUX_INITIATOR_DOWN:            '\u0000\u00bf', // 0b10111111
        EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN:  '\u0000\u003b', // 0b00111011
        // Refresh sequence.
        REFRESH_AUX_INITIATOR_DOWN:            '\u0000\u00c7', // 0b11000111
        // Quit indication.
        QUIT_DOWN:                             '\u0000\u00d3'  // 0b11010011
    };


    /** Mapping of message type to string representation. */
    ns.GREET_TYPE_MAPPING = {};
    for (var propName in ns.GREET_TYPE) {
        ns.GREET_TYPE_MAPPING[ns.GREET_TYPE[propName]] = propName;
    }


    /**
     * Converts a message type string to a number.
     *
     * @param typeString {string}
     * @return {integer}
     *     Number representing the message type.
     */
    ns.greetTypeToNumber = function(typeString) {
        return (typeString.charCodeAt(0) << 8)
                | typeString.charCodeAt(1);
    };


    /**
     * Converts a message type number to a message type string.
     *
     * @param typeNumber {integer}
     * @return {string}
     *     Two character string of message type.
     */
    ns.greetTypeFromNumber = function(typeNumber) {
        return String.fromCharCode(typeNumber >>> 8)
               + String.fromCharCode(typeNumber & 0xff);
    };


    // Checks whether a specific bit is set on a message type.
    function _isBitSetOnGreetType(greetType, bit) {
        if (typeof(greetType) === 'string') {
            greetType = ns.greetTypeToNumber(greetType);
        }
        return ((greetType & (1 << bit)) > 0);
    }


    /**
     * Inspects the AUX bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isAuxBitOnGreenType = function(greetType) {
        return _isBitSetOnGreetType(greetType, ns._AUX_BIT);
    };


    /**
     * Inspects the DOWN bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isDownBitOnGreetType = function(greetType) {
        return _isBitSetOnGreetType(greetType, ns._DOWN_BIT);
    };


    /**
     * Inspects the GKA bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isGkaBitOnGreetType = function(greetType) {
        return _isBitSetOnGreetType(greetType, ns._GKA_BIT);
    };


    /**
     * Inspects the SKE bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isSkeBitOnGreetType = function(greetType) {
        return _isBitSetOnGreetType(greetType, ns._SKE_BIT);
    };


    /**
     * Inspects the INIT bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isInitBitOnGreetType = function(greetType) {
        return _isBitSetOnGreetType(greetType, ns._INIT_BIT);
    };


    /**
     * Inspects the OPERATION bits of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {integer}
     *     Number of the operation.
     */
    ns.getOperationOnGreetType = function(greetType) {
        if (typeof(greetType) === 'string') {
            greetType = ns.greetTypeToNumber(greetType);
        }
        return (greetType & ns._OPERATION_MASK) >>> ns._OP_BITS;
    };


    /**
     * mpENC key agreement packet.
     *
     * @constructor
     * @private
     * @param source {string}
     *     Message originator (from).
     * @memberOf module:mpenc/greet/greeter
     *
     * @property source {string|object}
     *     Message originator (from) or a {GreetMessage} object to copy.
     * @property dest {string}
     *     Message destination (to).
     * @property greetType {string}
     *     mpENC protocol message type, one of {mpenc.ns.GREET_TYPE}.
     * @property sidkeyHint {string}
     *     One character string (a single byte), hinting at the right
     *     combination of session ID and group key used for a data message.
     * @property members {Array<string>}
     *     List (array) of all participating members.
     * @property intKeys {Array<string>}
     *     List (array) of intermediate keys for group key agreement.
     * @property nonces {Array<string>}
     *     Nonces of members for ASKE.
     * @property pubKeys {Array<string>}
     *     Ephemeral public signing key of members.
     * @property sessionSignature {string}
     *     Session acknowledgement signature using sender's static key.
     * @property signingKey {string}
     *     Ephemeral private signing key for session (upon quitting participation).
     * @property signature {string}
     *     Binary signature string for the message
     * @property signatureOk {bool}
     *     Indicator whether the message validates. after message decoding.
     * @property rawMessage {string}
     *     The raw message, after splitting off the signature. Can be used to
     *     re-verify the signature, if needed.
     * @property protocol {string}
     *     Single byte string indicating the protocol version using the binary
     *     version of the character.
     * @property data {string}
     *     Binary string containing the decrypted pay load of the message.
     */
    var GreetMessage = function(old) {
        old = old || {};
        this.source = old.source || '';
        this.dest = old.dest || '';
        this.greetType = old.greetType || null;
        this.sidkeyHint = old.sidkeyHint || null;
        this.members = old.members || [];
        this.intKeys = old.intKeys || [];
        this.nonces = old.nonces || [];
        this.pubKeys = old.pubKeys || [];
        this.sessionSignature = old.sessionSignature || null;
        this.signingKey = old.signingKey || null;
        this.signature = old.signature || null;
        this.signatureOk = old.signatureOk || false;
        this.rawMessage = old.rawMessage || null;
        this.data = old.data || null;
        this.metadata = old.metadata || null;
        return this;
    };


    /**
     * Returns a numeric representation of the message type.
     *
     * @method
     * @returns {integer}
     *     Message type as numeric value.
     */
    GreetMessage.prototype.getGreetTypeNumber = function() {
        return ns.greetTypeToNumber(this.greetType);
    };


    /**
     * Returns a string representation of the message type.
     *
     * @method
     * @returns {string}
     *     Message type as human readable string.
     */
    GreetMessage.prototype.getGreetTypeString = function() {
        return ns.GREET_TYPE_MAPPING[this.greetType];
    };


    /**
     * Sets a bit on the message type to a particular value.
     *
     * @private
     * @param {integer}
     *     Bit number to modify.
     * @param {bool}
     *     Value to set bit to.
     * @param {bool}
     *     If `true`, no checks for legal message transitions are performed
     *     (default: false).
     * @throws {Error}
     *     In case of a resulting illegal/non-existent message type.
     */
    GreetMessage.prototype._setBit= function(bit, value, noMessageCheck) {
        var newGreetTypeNum = this.getGreetTypeNumber();
        if (value === true || value === 1) {
            newGreetTypeNum |= 1 << bit;
        } else if (value === 0 || value === false) {
            newGreetTypeNum &= 0xffff - (1 << bit);
        } else {
            throw new Error("Illegal value for set/clear bit operation.");
        }
        var newGreetType = ns.greetTypeFromNumber(newGreetTypeNum);
        if (ns.GREET_TYPE_MAPPING[newGreetType] === undefined) {
            if (noMessageCheck !== true && noMessageCheck !== 1) {
                throw new Error("Illegal message type!");
            } else {
                this.greetType = newGreetType;
                logger.debug('Arrived at an illegal message type, but was told to ignore it: '
                             + newGreetType);
            }
        } else {
            this.greetType = newGreetType;
        }
    };


    /**
     * Reads a bit on the message type to a particular value.
     *
     * @private
     * @param {integer}
     *     Bit number to read.
     * @return {bool}
     *     Value of bit.
     */
    GreetMessage.prototype._readBit= function(bit) {
        return (_isBitSetOnGreetType(this.greetType, bit));
    };


    /**
     * Returns whether the message is for an auxiliary protocol flow.
     *
     * @method
     * @returns {bool}
     *     `true` for an auxiliary protocol flow.
     */
    GreetMessage.prototype.isAuxiliary = function() {
        return this._readBit(ns._AUX_BIT);
    };


    /**
     * Returns whether the message is for the downflow (broadcast).
     *
     * @method
     * @returns {bool}
     *     `true` for a downflow message.
     */
    GreetMessage.prototype.isDownflow = function() {
        return this._readBit(ns._DOWN_BIT);
    };


    /**
     * Sets the downflow bit on the message type.
     *
     * @method
     * @param {bool}
     *     If `true`, no checks for legal message transitions are performed
     *     (default: false).
     * @throws {Error}
     *     In case of a resulting illegal/non-existent message type.
     */
    GreetMessage.prototype.setDownflow = function(noMessageCheck) {
        return this._setBit(ns._DOWN_BIT, true, noMessageCheck);
    };


    /**
     * Returns whether the message is for the Group Key Agreement.
     *
     * @method
     * @returns {bool}
     *     `true` for a message containing GKA content.
     */
    GreetMessage.prototype.isGKA = function() {
        return this._readBit(ns._GKA_BIT);
    };


    /**
     * Clears the Group Key Agreement bit on the message type.
     *
     * @method
     * @param {bool}
     *     If `true`, no checks for legal message transitions are performed
     *     (default: false).
     * @throws {Error}
     *     In case of a resulting illegal/non-existent message type.
     */
    GreetMessage.prototype.clearGKA = function(noMessageCheck) {
        return this._setBit(ns._GKA_BIT, false, noMessageCheck);
    };


    /**
     * Returns whether the message is for the Signature Key Exchange.
     *
     * @method
     * @returns {bool}
     *     `true` for a message containing SKE content.
     */
    GreetMessage.prototype.isSKE = function() {
        return this._readBit(ns._SKE_BIT);
    };


    /**
     * Returns whether the message is from the protocol flow initiator.
     *
     * @method
     * @returns {bool}
     *     `true` for a message from the protocol flow initiator.
     */
    GreetMessage.prototype.isInitiator = function() {
        return this._readBit(ns._INIT_BIT);
    };


    /**
     * Clears the initiator bit on the message type.
     *
     * @method
     * @param {bool}
     *     If `true`, no checks for legal message transitions are performed
     *     (default: false).
     * @throws {Error}
     *     In case of a resulting illegal/non-existent message type.
     */
    GreetMessage.prototype.clearInitiator = function(noMessageCheck) {
        return this._setBit(ns._INIT_BIT, false, noMessageCheck);
    };


    /**
     * Returns the protocol operation of the message.
     *
     * @method
     * @returns {string}
     *     A clear text expression of the type of protocol operation.
     *     One of "DATA", "START", "INCLUDE", "EXCLUDE", "REFRESH" or "QUIT".
     */
    GreetMessage.prototype.getOperation = function() {
        return ns.OPERATION_MAPPING[(this.getGreetTypeNumber() & ns._OPERATION_MASK)
                                    >>> ns._OP_BITS];
    };


    ns.GreetMessage = GreetMessage;


    /**
     * Decodes a given TLV encoded Greet message into an object.
     *
     * @param message {string}
     *     A TLV string.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param sessionID {string}
     *     Session ID.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @returns {mpenc.greet.greeter.GreetMessage}
     *     Message as JavaScript object.
     */
    ns.decodeGreetMessage = function(message, pubKey) {
        var out = _decode(message);

        // Some specifics depending on the type of mpENC message.
        var sidkeyHash = '';
        _assert(!out.data);
        // Some sanity checks for keying messages.
        _assert(out.intKeys.length <= out.members.length,
                'Number of intermediate keys cannot exceed number of members.');
        _assert(out.nonces.length <= out.members.length,
                'Number of nonces cannot exceed number of members.');
        _assert(out.pubKeys.length <= out.members.length,
                'Number of public keys cannot exceed number of members.');

        // Check signature, if present.
        // TODO SECURITY REVIEW: why "if present"?
        if (out.signature) {
            if (!pubKey) {
                var index = out.members.indexOf(out.source);
                pubKey = out.pubKeys[index];
            }
            try {
                out.signatureOk = codec.verifyMessageSignature(codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                                            out.rawMessage,
                                                            out.signature,
                                                            pubKey,
                                                            sidkeyHash);
                _assert(out.signatureOk,
                        'Signature of message does not verify!');
            } catch (e) {
                out.signatureOk = false;
                _assert(out.signatureOk,
                        'Signature of message does not verify: ' + e + '!');
            }
        }
        return out;
    };


    var _decode = function(message) {
        // TODO(gk): high-priority - put range checks etc on the below
        var out = new GreetMessage();
        var debugOutput = [];
        var rest = message;

        rest = codec.popTLVMaybe(rest, _T.MESSAGE_SIGNATURE, function(value) {
            out.signature = value;
            debugOutput.push('messageSignature: ' + btoa(value));
        });
        if (rest !== message) {
            // there was a signature
            out.rawMessage = rest;
        }

        rest = codec.popStandardFields(rest,
            codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE, debugOutput);

        rest = codec.popTLV(rest, _T.GREET_TYPE, function(value) {
            out.greetType = value;
            debugOutput.push('greetType: 0x'
                             + ns.greetTypeToNumber(value).toString(16)
                             + ' (' + ns.GREET_TYPE_MAPPING[value] + ')');
        });

        rest = codec.popTLV(rest, _T.SOURCE, function(value) {
            out.source = value;
            debugOutput.push('from: ' + value);
        });

        rest = codec.popTLV(rest, _T.DEST, function(value) {
            out.dest = value;
            debugOutput.push('to: ' + value);
        });

        rest = codec.popTLVAll(rest, _T.MEMBER, function(value) {
            out.members.push(value);
            debugOutput.push('member: ' + value);
        });

        rest = codec.popTLVAll(rest, _T.INT_KEY, function(value) {
            out.intKeys.push(value);
            debugOutput.push('intKey: ' + btoa(value));
        });

        rest = codec.popTLVAll(rest, _T.NONCE, function(value) {
            out.nonces.push(value);
            debugOutput.push('nonce: ' + btoa(value));
        });

        rest = codec.popTLVAll(rest, _T.PUB_KEY, function(value) {
            out.pubKeys.push(value);
            debugOutput.push('pubKey: ' + btoa(value));
        });

        // For the proposal messages.
        rest = ns._popTLVMetadata(rest, out.source, false, function(value) {
            out.metadata = value;
        });

        rest = codec.popTLVMaybe(rest, _T.SESSION_SIGNATURE, function(value) {
            out.sessionSignature = value;
            debugOutput.push('sessionSignature: ' + btoa(value));
        });

        rest = codec.popTLVMaybe(rest, _T.SIGNING_KEY, function(value) {
            out.signingKey = value;
            debugOutput.push('signingKey: ' + btoa(value));
        });

        // TODO(xl): maybe complain if too much junk afterwards
        // Debugging output.
        logger.debug('mpENC decoded message debug: ', debugOutput);
        return out;
    };


    ns._popTLVMetadata = function(message, source, search, action) {
        // Decode a GreetingMetadata from the given TLV string, execute the
        // action on it (if one was decoded) and return the rest of the string.
        var prevPf, chainHash, parents = [];
        var rest = message;

        if (search) {
            // search until we find one
            rest = codec.popTLVUntil(rest, codec.TLV_TYPE.PREV_PF);
        }
        var newRest = codec.popTLVMaybe(rest, codec.TLV_TYPE.PREV_PF, function(value) {
            prevPf = value;
        });
        if (prevPf === undefined) {
            // just return rest if we don't immediately hit PREV_PF
            return rest;
        } else {
            rest = newRest;
        }

        rest = codec.popTLV(rest, codec.TLV_TYPE.CHAIN_HASH, function(value) {
            chainHash = value;
        });
        rest = codec.popTLVAll(rest, codec.TLV_TYPE.LATEST_PM, function(value) {
            parents.push(value);
        });

        action(GreetingMetadata.create(prevPf, chainHash, source, parents));
        return rest;
    };


    ns._determineFlowType = function(owner, prevMembers, members) {
        // Determine the mpENC GKA flow type (start/include/exclude/refresh)
        // from the requested prevMembers -> members abstract transition.
        _assert(owner);
        _assert(prevMembers.has(owner));
        _assert(members.has(owner));

        var ownSet = new ImmutableSet([owner]);
        prevMembers = prevMembers.subtract(ownSet);
        members = members.subtract(ownSet);
        _assert(prevMembers.size || members.size);

        var diff = prevMembers.diff(members);
        var include = diff[0];
        var exclude = diff[1];
        var keeping = prevMembers.intersect(members);

        // We can't both exclude and include members at the same time.
        _assert(!(exclude.size && include.size), "Cannot both exclude and join members.");

        if (include.size) {
            if (!keeping.size) {
                // no previous session, start() instead of include()
                return { greetType: ns.GREET_TYPE.INIT_INITIATOR_UP, members: members };
            } else {
                return { greetType: ns.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP, members: include };
            }
        } else if (exclude.size) {
            return { greetType: ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN, members: exclude };
        } else {
            return { greetType: ns.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN, members: members };
        }
    };


    /**
     * Encodes a given greet message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param message {mpenc.greet.greeter.GreetMessage}
     *     Message as JavaScript object.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {string}
     *     A TLV string.
     */
    ns.encodeGreetMessage = function(message, privKey, pubKey, paddingSize) {
        if (message === null || message === undefined) {
            return null;
        }
        paddingSize = paddingSize | 0;

        var out = codec.ENCODED_VERSION + codec.ENCODED_TYPE_GREET;
        // Process message attributes in this order:
        // greetType, source, dest, members, intKeys, nonces, pubKeys,
        // sessionSignature, signingKey
        out += codec.encodeTLV(codec.TLV_TYPE.GREET_TYPE, message.greetType);
        out += codec.encodeTLV(codec.TLV_TYPE.SOURCE, message.source);
        out += codec.encodeTLV(codec.TLV_TYPE.DEST, message.dest);
        if (message.members) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.MEMBER, message.members);
        }
        if (message.intKeys) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.INT_KEY, message.intKeys);
        }
        if (message.nonces) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.NONCE, message.nonces);
        }
        if (message.pubKeys) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.PUB_KEY, message.pubKeys);
        }
        // This is for the initial message of a key agreement, where we need
        // to send some extra metadata to help resolve concurrent operations.
        if (message.metadata) {
            var metadata = message.metadata;
            out += codec.encodeTLV(codec.TLV_TYPE.PREV_PF, metadata.prevPf);
            out += codec.encodeTLV(codec.TLV_TYPE.CHAIN_HASH, metadata.prevCh);
            out += codec._encodeTlvArray(codec.TLV_TYPE.LATEST_PM, metadata.parents.toArray());
        }
        //
        if (message.sessionSignature) {
            out += codec.encodeTLV(codec.TLV_TYPE.SESSION_SIGNATURE, message.sessionSignature);
        }
        if (message.signingKey) {
            out += codec.encodeTLV(codec.TLV_TYPE.SIGNING_KEY, message.signingKey);
        }
        // Sign `out` and prepend signature.
        var signature = codec.signMessage(codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                          out, privKey, pubKey);
        out = codec.encodeTLV(codec.TLV_TYPE.MESSAGE_SIGNATURE, signature) + out;

        return out;
    };


    ns._makePacketHash = function(packet) {
        // Calculate the hash of a packet. This is used for encode() to keep
        // track of packets that it sends out. (The packet-id depends on the
        // channelMembers, so we can't calculate it when we send the packet,
        // because we don't know what this will be when the server finally
        // echoes it back.)
        return utils.sha256(packet);
    };


    /**
     * Metadata about the context of a greeting.
     *
     * <p>This is attached to the initial message of every greeting operation.</p>
     *
     * <p>Users should prefer the <code>create</code> factory method instead of
     * this constructor.</p>
     *
     * @class
     * @private
     * @property prevPf {string}
     *      The packet-id of the previous operation's final message. If there
     *      was no previous operation, a random id should be used here instead.
     * @property prevCh {string}
     *      The ChainHash corresponding to prevPf.
     * @property author {string}
     *      The author of this initial message (i.e. initiator of the greeting).
     * @property parents {module:mpenc/helper/struct.ImmutableSet}
     *      The ids of the messages last seen by the author. (i.e. same as
     *      <code>session.transcript().max()</code>).
     * @see module:mpenc/greet/greeter.GreetingMetadata.create
     * @memberOf module:mpenc/greet/greeter
     */
    var GreetingMetadata = struct.createTupleClass("GreetingMetadata", "prevPf prevCh author parents");

    GreetingMetadata.prototype._postInit = function() {
        // hook for createTupleClass constructor
        _assert(typeof this.prevPf === "string");
        _assert(typeof this.prevCh === "string");
        _assert(typeof this.author === "string");
        _assert(this.parents instanceof ImmutableSet);
    };

    /**
     * Wrapper around the constructor that automatically converts its arguments
     * into types that are valid for the class.
     *
     * @param prevPf {string} See class docstring.
     * @param prevCh {string} See class docstring.
     * @param author {string} See class docstring.
     * @param parents {Iterable} See class docstring.
     * @returns {module:mpenc/greet/greeter.GreetingMetadata}
     */
    GreetingMetadata.create = function(prevPf, prevCh, author, parents) {
        return new this(prevPf, prevCh, author, ImmutableSet.from(parents));
    };

    ns.GreetingMetadata = GreetingMetadata;


    /**
     * Summary of an initial or final greeting (membership operation) message.
     *
     * @class
     * @private
     * @property pId {string}
     *      The packet-id of the message.
     * @property metadata {?module:mpenc/greet/greeter.GreetingMetadata}
     *      The metadata for the message, if it is an initial protocol flow message.
     * @property prevPi {?string}
     *      The previous pI for the protocol flow, if it is a final protocol flow message.
     * @property members {module:mpenc/helper/struct.ImmutableSet}
     *      The members of the new sub-session if the operation completes.
     * @see module:mpenc/greet/greeter.GreetingSummary.create
     * @memberOf module:mpenc/greet/greeter
     */
    var GreetingSummary = struct.createTupleClass("GreetingSummary", "pId metadata prevPi members");

    GreetingSummary.prototype._postInit = function() {
        // hook for createTupleClass constructor
        _assert(typeof this.pId === "string");
        _assert(this.metadata !== null || this.prevPi !== null);
        _assert(this.metadata === null || this.metadata instanceof GreetingMetadata);
        _assert(this.prevPi === null || typeof this.prevPi === "string");
        _assert(this.members instanceof ImmutableSet);
    };

    /**
     * @returns {boolean} <code>true</code> if this is an initial message.
     */
    GreetingSummary.prototype.isInitial = function() {
        return this.metadata !== null;
    };

    /**
     * @returns {boolean} <code>true</code> if this is a final message.
     */
    GreetingSummary.prototype.isFinal = function() {
        return this.prevPi !== null;
    };

    /**
     * @returns {string} Indicating the packet type.
     */
    GreetingSummary.prototype.packetType = function() {
        var a = 0 + this.isInitial();
        var b = 0 + this.isFinal();
        return "" + (a << 1 | b);
    };

    /**
     * Wrapper around the constructor that automatically converts its arguments
     * into types that are valid for the class.
     *
     * @param pId {string} See class docstring.
     * @param metadata {?module:mpenc/greet/greeter.GreetingMetadata} See class docstring.
     * @param prevPi {?string} See class docstring.
     * @param members {Iterable} See class docstring.
     * @returns {module:mpenc/greet/greeter.GreetingSummary}
     */
    GreetingSummary.create = function(pId, metadata, prevPi, members) {
        return new this(pId, metadata || null, prevPi || null, ImmutableSet.from(members));
    };

    ns.GreetingSummary = GreetingSummary;


    /**
     * Greeter tests for pI and pF messages, decodes these into GreetingSummary
     * and GreetingMetadata objects, and encodes local outgoing proposals for
     * Greetings.
     *
     * @class
     * @private
     * @param id {string}
     *      The owner of this greeter.
     * @param privKey {string}
     *      The static private key for this member.
     * @param pubKey {string}
     *      The static public key for this member.
     * @param staticPubKeyDir {{get: function}}
     *      Object with a 1-arg "get" method for obtaining static public keys
     *      for other members.
     * @memberOf module:mpenc/greet/greeter
     */
    var Greeter = function(id, privKey, pubKey, staticPubKeyDir) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        _assert(staticPubKeyDir.get(id) === pubKey, "bad static pubkey dir");

        // The current proposal started by the local user, if one is pending
        this.proposedGreeting = null;
        this.proposalHash = null;
        // The current operating greeting, if an operation is in progress.
        this.currentGreeting = null;
        this.currentPi = null;
    };

    /**
     * Partially decode a greeting proposal.
     *
     * Determine if the supplied message is an initial or final message of a
     * membership operation. If either, then a GreetingSummary object is
     * returned, otherwise <code>null</code>.
     *
     * This is called *before* the packet is accepted or rejected. Therefore,
     * it should not mutate state in a way that is non-reversible, since the
     * proposal may be rejected by the resolution mechanism.
     *
     * Roughly, this can be thought of as the analogue of a "peek" or "inspect"
     * method that exists in some APIs for other things.
     *
     * @param prevMembers {module:mpenc/helper/struct.ImmutableSet}
     *      Membership of the previous (i.e. currently active) sub-session.
     * @param pubtxt {string}
     *      The original data received from the transport.
     * @param from {string}
     *      The unauthenticated (transport) sender of the message.
     * @param makePacketId {function}
     *      0-arg factory to generate the packet-id for this packet. Should
     *      only be called if absolutely necessary, for efficiency, e.g. not
     *      called in most cases when returning <code>null</code>.
     * @returns {?module:mpenc/greet/greeter.GreetingSummary}
     */
    Greeter.prototype.partialDecode = function(prevMembers, pubtxt, from, makePacketId) {
        var message = codec.decodeWirePacket(pubtxt);
        if (message.type !== codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE) {
            return null;
        }
        var rest = message.content;

        rest = codec.popTLVMaybe(rest, codec.TLV_TYPE.MESSAGE_SIGNATURE, function() {});
        rest = codec.popStandardFields(rest, codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE);
        // Find all of the relavant data from the message.
        var mType, source, dest, members = [];
        rest = codec.popTLVUntil(rest, codec.TLV_TYPE.GREET_TYPE);
        rest = codec.popTLV(rest, codec.TLV_TYPE.GREET_TYPE, function(value) {
            mType = value;
        });
        rest = codec.popTLV(rest, codec.TLV_TYPE.SOURCE, function(value) {
            source = value;
        });
        rest = codec.popTLV(rest, codec.TLV_TYPE.DEST, function(value) {});
        rest = codec.popTLVAll(rest, codec.TLV_TYPE.MEMBER, function(value) {
            members.push(value);
        });

        var greetingSummary = null;

        // There _is_ a shorter way to test for these, but I decided to be explicit.
        // Initial type messages need to have their metadata extracted.
        if (mType === ns.GREET_TYPE.INIT_INITIATOR_UP ||
           mType === ns.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP ||
           mType === ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN && members.length > 1) {
            ns._popTLVMetadata(rest, source, true, function(value) {
                greetingSummary = GreetingSummary.create(makePacketId(), value, null, members);
            });
        }
        // Downflow confirm messages require testing for final messages.
        else if (mType === ns.GREET_TYPE.INIT_PARTICIPANT_CONFIRM_DOWN ||
                mType === ns.GREET_TYPE.INCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN ||
                mType === ns.GREET_TYPE.EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN) {
            if (!this.currentGreeting) {
                _logIgnored(this.id, makePacketId(),
                    "got a downflow message but there is no current Greeting");
                return null;
            }
            // Test if this is the final message.
            if (this.currentGreeting._expectsFinalMessage(makePacketId, source)) {
                greetingSummary = GreetingSummary.create(makePacketId(), null, this.currentPi, members);
            }
        }
        // Refresh and exclude-everyone-except-self messages are initial+final packets.
        else if (mType === ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN && members.length === 1 ||
           mType === ns.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN) {
            ns._popTLVMetadata(rest, source, true, function(value) {
                var pId = makePacketId();
                greetingSummary = GreetingSummary.create(pId, value, pId, members);
            });
        }
        // TODO(xl): QUIT is pending removal from the spec, we shouldn't ever see this
        else if (mType === ns.GREET_TYPE.QUIT_DOWN) {
            throw new Error("unsupported greet type: QUIT_DOWN");
        }
        // Not an initial or final greeter packet
        else {
            return null;
        }

        if (greetingSummary && greetingSummary.metadata && (from === this.id || source === this.id)) {
            var pHash = ns._makePacketHash(message.content);
            if (this.proposalHash !== pHash) {
                _logIgnored(this.id, pHash, "(pHash) it claims to be a pI from us but we did not send it");
                return null;
            }
        }

        return greetingSummary;
    };

    /**
     * Encode a new Greeting proposal, given local context.
     *
     * This encodes only initial packets, and returns raw data to send to the
     * other members.
     *
     * This is called *before* the packet is accepted or rejected. Therefore,
     * it should not mutate state in a way that is non-reversible, since the
     * operation may be rejected by the resolution mechanism.
     *
     * @param prevGreetStore {?module:mpenc/greet/greeter.GreetStore}
     *      Greeting state of the previous (i.e. currently active) sub-session.
     * @param prevMembers {?module:mpenc/helper/struct.ImmutableSet}
     *      Membership of the previous (i.e. currently active) sub-session.
     * @param members {module:mpenc/helper/struct.ImmutableSet}
     *      The desired members of the new sub-session.
     * @param metadata {?module:mpenc/greet/greeter.GreetingMetadata}
     *      The metadata for the message, to help preserve ordering.
     * @returns {string}
     *      Encoded data to send out to the transport.
     */
    Greeter.prototype.encode = function(prevGreetStore, prevMembers, members, metadata) {
        prevMembers = prevMembers || new ImmutableSet([this.id]);
        _assert(metadata);
        _assert(prevMembers.has(this.id));
        _assert(members.has(this.id));

        var message = null;
        var greeting = new Greeting(this, prevGreetStore);
        var greetData = ns._determineFlowType(this.id, prevMembers, members);
        switch (greetData.greetType) {
            case ns.GREET_TYPE.INIT_INITIATOR_UP:
                message = greeting.start(greetData.members.toArray());
                break;
            case ns.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP:
                message = greeting.include(greetData.members.toArray());
                break;
            case ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN:
                message = greeting.exclude(greetData.members.toArray());
                break;
            case ns.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN:
                message = greeting.refresh();
                break;
            case ns.GREET_TYPE.QUIT_DOWN:
                message = greeting.quit();
                break;
            default:
                throw new Error("Invalid greet type");
        }

        _assert(message.metadata === null);
        message.metadata = metadata;
        // no need to set greeting.metadata here, it will be set automatically
        // by greeting.recv() if the proposal is accepted
        var payLoad = ns.encodeGreetMessage(message, greeting.getEphemeralPrivKey(),
            greeting.getEphemeralPubKey());

        this.proposedGreeting = greeting;
        this.proposalHash = ns._makePacketHash(payLoad);

        return codec.encodeWirePacket(payLoad);
    };

    /**
     * Decode an incoming accepted Greeting, assuming local context.
     *
     * This decodes only initial packets, and is called *after* the packet has
     * been accepted by the resolution mechanism. Therefore, it may (and must)
     * mutate local state as appropriate for the operation.
     *
     * After this method returns a Greeting, the params [pubtxt, sender] that
     * were input here are automatically also passed into its recv() method.
     * This allows the Greeting to complete within one packet if necessary, and
     * might also simplify the object's constructor.
     *
     * @param prevGreetStore {module:mpenc/greet/greeter.GreetStore}
     *      Greeting state of the previous (i.e. currently active) sub-session.
     * @param prevMembers {module:mpenc/helper/struct.ImmutableSet}
     *      Membership of the previous (i.e. currently active) sub-session.
     * @param pubtxt {string}
     *      The original data received from the transport.
     * @param from {string}
     *      The unauthenticated (transport) sender of the message.
     * @param pId {string}
     *      Packet-id of this packet, already calculated earlier.
     * @returns {module:mpenc/greet/greeter.Greeting}
     * @throws This method (and future versions of it) tries to avoid throwing
     *      an error here, and instead these are detected during partialDecode.
     *      However, if this does need to occur for whatever reason, then the
     *      caller will treat this as an *immediate failure* of the operation.
     */
    Greeter.prototype.decode = function(prevGreetStore, prevMembers, pubtxt, from, pId) {
        var message = codec.decodeWirePacket(pubtxt);
        var pHash = ns._makePacketHash(message.content);

        // This is our message, so reuse the already-created greeting.
        if (this.proposedGreeting && this.proposalHash === pHash) {
            this.currentGreeting = this.proposedGreeting;
        }
        // Otherwise, just create a new greeting.
        else {
            _assert(message.source !== this.id);
            this.currentGreeting = new Greeting(this, prevGreetStore);
        }

        // Clear the proposedGreeting field.
        this.currentPi = pId;
        this.proposedGreeting = null;
        this.proposalHash = null;

        // When settled, clear the currentGreeting field.
        var self = this;
        var clear = function(r) {
            self.currentGreeting = null;
            async.exitFinally(r);
        };
        this.currentGreeting.getPromise().then(clear, clear);

        return this.currentGreeting;
    };

    ns.Greeter = Greeter;


    /**
     * "Enumeration" defining the different stable and intermediate states of
     * the mpENC module.
     *
     * @property NULL {integer}
     *     Uninitialised (default) state.
     * @property INIT_UPFLOW {integer}
     *     During process of initial protocol upflow.
     * @property INIT_DOWNFLOW {integer}
     *     During process of initial protocol downflow.
     * @property READY {integer}
     *     Default state during general usage of mpENC. No protocol/key
     *     negotiation going on, and a valid group key is available.
     * @property AUX_UPFLOW {integer}
     *     During process of auxiliary protocol upflow.
     * @property AUX_DOWNFLOW {integer}
     *     During process of auxiliary protocol downflow.
     * @property QUIT {integer}
     *     After quitting participation.
     */
    ns.STATE = {
        NULL:          0x00,
        INIT_UPFLOW:   0x01,
        INIT_DOWNFLOW: 0x02,
        READY:         0x03,
        AUX_UPFLOW:    0x04,
        AUX_DOWNFLOW:  0x05,
        QUIT:          0x06,
    };

    /** Mapping of state to string representation. */
    ns.STATE_MAPPING = {};
    for (var propName in ns.STATE) {
        ns.STATE_MAPPING[ns.STATE[propName]] = propName;
    }


    /**
     * GreetStore holds all of the public and private data required to start
     * a Greeting operation, that may be based on the result of previously
     * completed operations.
     *
     * @constructor
     * @private
     * @param id {string}
     *      The owner of this greeter.
     * @param [opState] {number}
     *      The state of the last Greeting; must be NULL or READY.
     * @param [members] {array<string>}
     *      The members for the greet session.
     *
     * @param [sessionId] {string}
     *      The id for the session.
     * @param [ephemeralPrivKey] {string}
     *      The ephemeral private key for <b>this</b> member.
     * @param [ephemeralPubKey] {string}
     *      The ephemeral public key for <b>this</b> member.
     * @param [nonce] {string}
     *      The nonce for <b>this</b> member.
     * @param [ephemeralPubKeys] {array<string>}
     *      The ephemeral signing keys for the other members in the chat session.
     * @param [nonces] {array<string>}
     *      The nonces for the other members in the chat session.
     *
     * @param [groupKey] {string}
     *      The group secret key for this session.
     * @param [privKeyList] {array<string>}
     *      The list of private contributions for <b>this</b> member.
     * @param [intKeys] {array<string>}
     *      The list of previous initial keys for all members.
     * @memberOf module:mpenc/greet/greeter
     */
    var GreetStore = function(id, opState, members,
            sessionId, ephemeralPrivKey, ephemeralPubKey, nonce, ephemeralPubKeys, nonces,
            groupKey, privKeyList, intKeys) {
        this.id = id;
        this._opState = opState || ns.STATE.NULL;
        this.members = utils.clone(members) || [];
        _assert(this._opState === ns.STATE.READY || this._opState === ns.STATE.NULL,
            "tried to create a GreetStore on a state other than NULL or READY: " +
            ns.STATE_MAPPING[opState]);

        // Aske Objects.
        this.sessionId = utils.clone(sessionId) || null;
        this.ephemeralPrivKey = utils.clone(ephemeralPrivKey) || null;
        this.ephemeralPubKey = utils.clone(ephemeralPubKey) || null;
        this.nonce = utils.clone(nonce) || null;
        this.ephemeralPubKeys = utils.clone(ephemeralPubKeys) || null;
        this.nonces = utils.clone(nonces) || null;

        // Cliques Objects.
        this.groupKey = utils.clone(groupKey) || null;
        this.privKeyList = utils.clone(privKeyList) || [];
        this.intKeys = utils.clone(intKeys) || [];
        // Create the map of members : ephemeralPubKeys.
        this.pubKeyMap = {};
        if (members) {
            _assert(ephemeralPubKeys, 'ephemeral pubkeys null when members present.');
            _assert(members.length === ephemeralPubKeys.length, 'Length of members/pub keys mismatch,'
                    + ' members.length = ' + members.length + " ephemeralPubKeys.length = " +
                    ephemeralPubKeys.length);

            for (var i = 0; i < members.length; i++) {
                this.pubKeyMap[members[i]] = ephemeralPubKeys[i];
            }
        }

        return this;
    };

    ns.GreetStore = GreetStore;


    /**
     * Implementation of a protocol handler with its state machine.
     *
     * The instantiated types for <code>SendingReceiver</code> are:
     *
     * <ul>
     * <li><code>{@link module:mpenc/greet/greeter.Greeting#recv|RecvInput}</code>:
     *      {@link module:mpenc/helper/utils.RawRecv}</li>
     * <li><code>{@link module:mpenc/greet/greeter.Greeting#onSend|SendOutput}</code>:
     *      {@link module:mpenc/helper/utils.RawSend}</li>
     * </ul>
     *
     * @class
     * @private
     * @param greeter {module:mpenc/greet/greeter.Greeter}
     *      Context of this Greeting operation with various static information.
     * @param [store] {module:mpenc/greet/greeter.GreetStore}
     *      State at the end of the previously-completed operation, if any.
     * @memberOf module:mpenc/greet/greeter
     * @implements module:mpenc/helper/utils.SendingReceiver
     */
    var Greeting = function(greeter, store) {
        store = store || new GreetStore(greeter.id);
        this.id = greeter.id;
        this.privKey = greeter.privKey;
        this.pubKey = greeter.pubKey;
        this.staticPubKeyDir = greeter.staticPubKeyDir;

        this._opState = store._opState;
        this._send = new async.Observable(true);

        var cliquesMember = new cliques.CliquesMember(greeter.id);
        cliquesMember.members = utils.clone(store.members);
        cliquesMember.groupKey = utils.clone(store.groupKey);
        cliquesMember.privKeyList = utils.clone(store.privKeyList);
        cliquesMember.intKeys = utils.clone(store.intKeys);
        this.cliquesMember = cliquesMember;

        var askeMember = new ske.SignatureKeyExchangeMember(greeter.id);
        askeMember.staticPrivKey = greeter.privKey;
        askeMember.staticPubKeyDir = greeter.staticPubKeyDir;
        askeMember.sessionId = store.sessionId;
        askeMember.members = utils.clone(store.members);
        askeMember.ephemeralPrivKey = utils.clone(store.ephemeralPrivKey);
        askeMember.ephemeralPubKey = utils.clone(store.ephemeralPubKey);
        askeMember.nonce = utils.clone(store.nonce);
        askeMember.ephemeralPubKeys = utils.clone(store.ephemeralPubKeys);
        askeMember.nonces = utils.clone(store.nonces);
        askeMember.authenticatedMembers = [];
        this.askeMember = askeMember;

        this.metadata = null;
        this._metadataIsAuthenticated = false;
        this._recvOwnAuthMessage = false;
        this._nextMembers = null;

        var self = this;
        this._finished = 0; // 0 = pending,
        // 1 = completed (finished with success, or fulfilled in JS-Promise terminology)
        // -1 = failed (finished with failure, or rejected in JS-Promise terminology)
        this._abortReason = null;
        this._promise = async.newPromiseAndWriters();

        // We can keep the old state around for further use.
        this.prevState = store;
        return this;
    };
    ns.Greeting = Greeting;

    /**
     * Get the previous GreetStore for this Greeting.
     *
     * @returns The previous GreetStore for the last session.
     */
    Greeting.prototype.getPrevState = function() {
        return this.prevState;
    };

    /**
     * Members in the previous sub-session that this Greeting was started from.
     *
     * @returns {module:mpenc/helper/struct.ImmutableSet} The members of the
     *      previous Greeting.
     */
    Greeting.prototype.getPrevMembers = function() {
        var prevMembers = this.prevState.members;
        return new ImmutableSet(prevMembers && prevMembers.length ? prevMembers : [this.id]);
    };

    /**
     * Members in the next session that this Greeting is trying to reach.
     *
     * @returns {module:mpenc/helper/struct.ImmutableSet} The members for this
     *      Greeting.
     * @throws If called before recv() has accepted the initial packet.
     */
    Greeting.prototype.getNextMembers = function() {
        _assert(this._nextMembers); // not set until we got first packet
        return this._nextMembers;
    };

    /**
     * Get the metadata associated with this Greeting.
     *
     * @returns {module:mpenc/greet/greeter.GreetingMetadata} The metadata for
     *      this Greeting.
     */
    Greeting.prototype.getMetadata = function() {
        return this.metadata;
    };

    /**
     * @returns {boolean} Whether the metadata associated with the initial
     *      packet was authenticated against its claimed author/source by this
     *      operation itself. If not, then a higher layer (e.g. Session) must
     *      do this retroactively.
     */
    Greeting.prototype.metadataIsAuthenticated = function () {
        return this._metadataIsAuthenticated;
    };

    /**
     * @returns {module:mpenc/greet/greeter.GreetStore} Resulting greet state
     *      at the completion of the Greeting operation.
     * @throws If the operation is not yet complete.
     */
    Greeting.prototype.getResultState = function () {
        this._checkComplete();
        return new GreetStore(
            this.id, this._opState, this.askeMember.members, this.askeMember.sessionId,
            this.askeMember.ephemeralPrivKey, this.askeMember.ephemeralPubKey, this.askeMember.nonce,
            this.askeMember.ephemeralPubKeys, this.askeMember.nonces,
            this.cliquesMember.groupKey, this.cliquesMember.privKeyList, this.cliquesMember.intKeys);
    };

    /**
     * @returns {module:mpenc/greet/greeter.GreetStore} Resulting session id
     *      for the next sub-session, as determined by the Greeting operation.
     * @throws If the operation is not yet complete.
     */
    Greeting.prototype.getResultSId = function () {
        this._checkComplete();
        return this.askeMember.sessionId;
    };

    Greeting.prototype._checkComplete = function() {
        if (!this._finished) {
            throw new Error("OperationInProgress");
        } else if (this._finished === -1) {
            throw new Error("OperationFailed: caused by " + this._abortReason.stack + "\nre-thrown at: ");
        }
    };

    Greeting.prototype.getPromise = function () {
        return this._promise.promise;
    };

    Greeting.prototype._updateOpState = function(state) {
        // Update the operation state.
        _assert(typeof state === "number");
        logger.debug('Reached new state: ' + ns.STATE_MAPPING[state]);
        this._opState = state;
    };

    Greeting.prototype._assertStartState = function(valid, message) {
        _assert(!this._finished);
        // Check the operation state against an array of valid values.
        var state = this._opState;
        _assert(valid.some(function(v) {
            return state === v;
        }, this), message + " but state was: " + ns.STATE_MAPPING[state]);
    };

    Greeting.prototype._encodeAndPublish = function(message, state) {
        // Encode a GreetMessage and publish it to send-subscribers.
        _assert(message);
        var payload = ns.encodeGreetMessage(
            message,
            this.getEphemeralPrivKey(),
            this.getEphemeralPubKey());
        var recipients = message.dest ? new ImmutableSet([message.dest]) : this.getNextMembers();
        this._send.publish({ pubtxt: codec.encodeWirePacket(payload), recipients: recipients });
        if (state !== undefined) {
            this._updateOpState(state);
        }
    };

    /**
     * @inheritDoc
     */
    Greeting.prototype.onSend = function(subscriber) {
        return this._send.subscribe(subscriber);
    };

    /**
     * Mechanism to start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *      The message to commence the intial key exchange.
     */
    Greeting.prototype.start = function(otherMembers) {
        this._assertStartState([ns.STATE.NULL],
                'start() can only be called from an uninitialised state.');
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        var message = this._mergeMessages(cliquesMessage, askeMessage);
        message.greetType = ns.GREET_TYPE.INIT_INITIATOR_UP;

        this._updateOpState(ns.STATE.INIT_UPFLOW);
        this._nextMembers = new ImmutableSet(otherMembers.concat([this.id]));
        return message;
    };


    /**
     * Mechanism to start a new upflow for including new members.
     *
     * @method
     * @param includeMembers {Array}
     *     Array of members to include into the group.
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *      The message to commence inclusion.
     */
    Greeting.prototype.include = function(includeMembers) {
        this._assertStartState([ns.STATE.READY],
                'include() can only be called from a ready state.');
        _assert(includeMembers && includeMembers.length !== 0, 'No members to add.');
        var cliquesMessage = this.cliquesMember.akaJoin(includeMembers);
        var askeMessage = this.askeMember.join(includeMembers);

        var message = this._mergeMessages(cliquesMessage, askeMessage);
        message.greetType = ns.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP;
        this._updateOpState(ns.STATE.AUX_UPFLOW);
        this._nextMembers = new ImmutableSet(this.prevState.members.concat(includeMembers));
        return message;
    };


    /**
     * Mechanism to start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *      The message to commence exclusion.
     */
    Greeting.prototype.exclude = function(excludeMembers) {
        this._assertStartState([ns.STATE.READY],
                'exclude() can only be called from a ready state.');
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        var message = this._mergeMessages(cliquesMessage, askeMessage);
        message.greetType = ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN;

        // We need to update the session state.
        this.sessionId = this.askeMember.sessionId;
        this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
        this.groupKey = this.cliquesMember.groupKey;

        // this used to redirect to quit() if there was 1 remaining member,
        // but now this case is handled better by Greeter.partialDecode
        this._updateOpState(
            this.askeMember.isSessionAcknowledged() ? ns.STATE.READY : ns.STATE.AUX_DOWNFLOW);
        this._nextMembers = new ImmutableSet(this.prevState.members).subtract(new ImmutableSet(excludeMembers));
        return message;
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @method
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *      The message to commence quitting.
     */
    Greeting.prototype.quit = function() {
        if (this._opState === ns.STATE.QUIT) {
            return; // Nothing do do here.
        }

        _assert(this.getEphemeralPrivKey() !== null,
                'Not participating.');

        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();

        var message = this._mergeMessages(null, askeMessage);
        message.greetType = ns.GREET_TYPE.QUIT_DOWN;
        this._updateOpState(ns.STATE.QUIT);
        return message;
    };


    /**
     * Mechanism to refresh group key.
     *
     * @method
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *     The message to commence key refresh.
     *
     */
    Greeting.prototype.refresh = function() {
        this._assertStartState([ns.STATE.READY, ns.STATE.INIT_DOWNFLOW, ns.STATE.AUX_DOWNFLOW],
                'refresh() can only be called from a ready or downflow states.');
        var cliquesMessage = this.cliquesMember.akaRefresh();

        var message = this._mergeMessages(cliquesMessage, null);
        message.greetType = ns.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN;
        // We need to update the group key.
        this.groupKey = this.cliquesMember.groupKey;
        this._nextMembers = new ImmutableSet(this.prevState.members);
        return message;
    };


    /**
     * @inheritDoc
     */
    Greeting.prototype.recv = function(recv_in) {
        _assert(!this._finished);
        var pubtxt = recv_in.pubtxt;
        var from = recv_in.sender;
        var message = codec.decodeWirePacket(pubtxt);
        if (message.type !== codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE) {
            return false;
        }
        var content = message.content;

        var decodedMessage = null;
        if (this.getEphemeralPubKey()) {
            // In case of a key refresh (groupKey existent),
            // the signing pubKeys won't be part of the message.
            // TODO(gk): xl: but we're not checking if this is a key refresh here?
            var signingPubKey = this.getEphemeralPubKey(from);
            decodedMessage = ns.decodeGreetMessage(content, signingPubKey);
        } else {
            decodedMessage = ns.decodeGreetMessage(content);
        }

        if (this.metadata) {
            if (decodedMessage.metadata) {
                var pHash = ns._makePacketHash(content);
                _logIgnored(this.id, pHash, "(pHash) it has metadata but greeting is already started");
                return true; // TODO(xl): tweak as per "identify" comment
            }
        } else {
            if (!decodedMessage.metadata) {
                var pHash = ns._makePacketHash(content);
                _logIgnored(this.id, pHash, "(pHash) it has no metadata but greeting not yet started");
                return true; // TODO(xl): tweak as per "identify" comment
            }
            this.metadata = decodedMessage.metadata;
            // TODO(xl): #2350 need to tweak ske to verify metadata, e.g. by hashing
            // the packet-id of the proposal into the session-id
        }

        var prevState = this._opState;
        var result = this._processMessage(decodedMessage);
        if (result === null) {
            return true; // TODO(xl): tweak as per "identify" comment
        }
        if (result.decodedMessage) {
            this._encodeAndPublish(result.decodedMessage);
        }
        if (result.newState) {
            this._updateOpState(result.newState);
        }
        return true;
    };


    /**
     * Handles greet (key agreement) protocol execution with all participants.
     *
     * @private
     * @param message {module:mpenc/greet/greeter.GreetMessage}
     *     Received message (decoded).
     * @returns {Object}
     *     Object containing any response output message as
     *     {GreetMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the Greeting state in
     *     attribute `newState`.
     */
    Greeting.prototype._processMessage = function(message) {
        logger.debug('Processing message of type '
                     + message.getGreetTypeString());
        if (this._opState === ns.STATE.QUIT) {
            // We're not par of this session, get out of here.
            logger.debug("Ignoring message as we're in state QUIT.");
            // TODO(xl): identify if this message belongs to this greeting or not
            // and in recv(), distinguish between these two cases (return true vs false)
            return null;
        }

        if (!this._nextMembers) {
            this._nextMembers = new ImmutableSet(message.members);
        }

        // State transitions.
        var newState = null;

        // If I'm not part of it any more, go and quit.
        if (message.members && (message.members.length > 0)
                && (message.members.indexOf(this.id) === -1)) {
            _assert(this._opState !== ns.STATE.QUIT);
            if (message.members.length === 1) {
                // 1-member exclude-operations complete in 1 packet; we know this even
                // if we're the one being excluded - partialDecode recognises this and
                // sets the packet as "final", so we must be consistent here and resolve
                // the Greeting too. otherwise HybridSession gets confused (rightly so)
                _assert(!this._finished);
                this._promise.resolve(this);
                this._finished = 1;
            }
            return { decodedMessage: null,
                     newState: ns.STATE.QUIT };
        }

        // Ignore the message if it is from me.
        if (message.source === this.id) {
            if (message.isDownflow()) {
                // TODO: could check that we actually sent this message
                this._recvOwnAuthMessage = true;
            }

            newState = this._maybeFulfill() ? ns.STATE.READY : newState;
            return { decodedMessage: null,
                     newState: newState };
        }

        // Ignore the message if it is not for me.
        if ((message.dest !== '') && (message.dest !== this.id)) {
            return { decodedMessage: null,
                     newState: null };
        }

        // Response message
        var inCliquesMessage = this._getCliquesMessage(message);
        var inAskeMessage = this._getAskeMessage(message);
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;

        // Three cases: QUIT, upflow or downflow message.
        if (message.greetType === ns.GREET_TYPE.QUIT_DOWN) {
            // QUIT message.
            //_assert(message.signingKey,
            //        'Inconsistent message content with message type (signingKey).');
            // TODO: not currently publishing signatures; see ske.js for details
        } else if (message.isDownflow()) {
            // Downflow message.
            if (message.isGKA()) {
                this.cliquesMember.downflow(inCliquesMessage);
            }
            if (message.isSKE()) {
                outAskeMessage = this.askeMember.downflow(inAskeMessage);
            }
            outMessage = this._mergeMessages(null, outAskeMessage);
            if (outMessage) {
                outMessage.greetType = message.greetType;
                // In case we're receiving it from an initiator.
                outMessage.clearInitiator(true);
                // Confirmations (subsequent) downflow messages don't have a GKA.
                outMessage.clearGKA();
                // Handle state transitions.
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_DOWNFLOW;
                } else {
                    newState = ns.STATE.INIT_DOWNFLOW;
                }
            } else {
                // TODO(gk): what happens here?
            }
        } else {
            // Upflow message.
            outCliquesMessage = this.cliquesMember.upflow(inCliquesMessage);
            outAskeMessage = this.askeMember.upflow(inAskeMessage);
            outMessage = this._mergeMessages(outCliquesMessage, outAskeMessage);
            outMessage.greetType = message.greetType;
            // In case we're receiving it from an initiator.
            outMessage.clearInitiator();
            // Handle state transitions.
            if (outMessage.dest === '') {
                outMessage.setDownflow();
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_DOWNFLOW;
                } else {
                    newState = ns.STATE.INIT_DOWNFLOW;
                }
            } else {
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_UPFLOW;
                } else {
                    newState = ns.STATE.INIT_UPFLOW;
                }
            }
        }

        newState = this._maybeFulfill() ? ns.STATE.READY : newState;
        if (outMessage) {
            logger.debug('Sending message of type '
                         + outMessage.getGreetTypeString());
        } else {
            logger.debug('No message to send.');
        }
        return { decodedMessage: outMessage,
                 newState: newState };
    };


    Greeting.prototype._maybeFulfill = function() {
        // Check if the operation is complete.
        // If so, set public variables and fire hooks (e.g. promises)
        var isRefresh = this.getPrevMembers().equals(this.getNextMembers());
        if (isRefresh || this.askeMember.isSessionAcknowledged() && this._recvOwnAuthMessage) {
            // check that we got where we wanted to go
            _assert(this.getNextMembers().equals(new ImmutableSet(this.askeMember.members)));

            // We have seen and verified all broadcasts from others.
            // Let's update our state information.
            this.sessionId = this.askeMember.sessionId;
            this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
            this.groupKey = this.cliquesMember.groupKey;

            _assert(!this._finished);
            this._promise.resolve(this);
            this._finished = 1;

            return true;
        }
        return false;
    };


    /**
     * Fail the greeting, and errback any Deferreds passed to clients.
     *
     * This is a response method, and should *not* send out any packets.
     *
     * This provides a way for an external component that manages this one,
     * to fail the operation for reasons that are external to the specifics of
     * the membership operation. For example, if we have left the channel, or
     * if another member has also left the channel.
     */
    Greeting.prototype.fail = function(reason) {
        _assert(reason instanceof Error);
        _assert(!this._finished);
        this._promise.reject(reason);
        this._abortReason = reason;
        this._finished = -1;
    };


    Greeting.prototype._expectsFinalMessage = function(makePacketId, source) {
        // check to see if message matches what the current greeting is expecting
        var yetToAuthenticate = this.askeMember.yetToAuthenticate();
        _assert(yetToAuthenticate.length > 0 || !this._recvOwnAuthMessage,
                "Members have all been authenticated.");

        if (source === this.id) {
            if (yetToAuthenticate.length === 0 && !this._recvOwnAuthMessage) {
                return true;
            }
        } else if (yetToAuthenticate.length === 1 && this._recvOwnAuthMessage) {
            if (source === yetToAuthenticate[0]) {
                return true;
            }
            _logIgnored(this.id, makePacketId(), "looks like final message but not from expected source: "
                + source + " vs expected " + yetToAuthenticate[0]);
        }

        return false;
    };


    /**
     * Merges the contents of the messages for ASKE and CLIQUES into one message.
     *
     * @private
     * @param cliquesMessage {mpenc.greet.cliques.CliquesMessage}
     *     Message from CLIQUES protocol workflow.
     * @param askeMessage {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Message from ASKE protocol workflow.
     * @returns {module:mpenc/greet/greeter.GreetMessage}
     *     Joined message (not wire encoded).
     */
    Greeting.prototype._mergeMessages = function(cliquesMessage, askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = new GreetMessage();
        newMessage.source = this.id;

        if (cliquesMessage && askeMessage) {
            _assert(cliquesMessage.source === askeMessage.source,
                    "Message source mismatch, this shouldn't happen.");
            _assert(cliquesMessage.dest === askeMessage.dest,
                    "Message destination mismatch, this shouldn't happen.");
        }

        // Empty objects to simplify further logic.
        cliquesMessage = cliquesMessage || {};
        askeMessage = askeMessage || {};

        newMessage.dest = cliquesMessage.dest || askeMessage.dest || '';
        newMessage.members = cliquesMessage.members || askeMessage.members;
        newMessage.intKeys = cliquesMessage.intKeys || null;
        newMessage.nonces = askeMessage.nonces || null;
        newMessage.pubKeys = askeMessage.pubKeys || null;
        newMessage.sessionSignature = askeMessage.sessionSignature || null;
        newMessage.signingKey = askeMessage.signingKey || null;

        return newMessage;
    };


    /**
     * Extracts a CLIQUES message out of the received protocol handler message.
     *
     * @private
     * @param message {module:mpenc/greet/greeter.GreetMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.cliques.CliquesMessage}
     *     Extracted message.
     */
    Greeting.prototype._getCliquesMessage = function(message) {
        var newMessage = cliques.CliquesMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.members = message.members;
        newMessage.intKeys = message.intKeys;

        // Upflow or downflow.
        if (message.isDownflow()) {
            newMessage.flow = 'down';
        } else {
            newMessage.flow = 'up';
        }

        // IKA or AKA.
        if (message.getOperation() === 'START') {
            newMessage.agreement = 'ika';
        } else {
            newMessage.agreement = 'aka';
        }

        return newMessage;
    };


    /**
     * Extracts a ASKE message out of the received protocol handler message.
     *
     * @private
     * @param message {module:mpenc/greet/greeter.GreetMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    Greeting.prototype._getAskeMessage = function(message) {
        var newMessage = ske.SignatureKeyExchangeMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.members = message.members;
        newMessage.nonces = message.nonces;
        newMessage.pubKeys = message.pubKeys;
        newMessage.sessionSignature = message.sessionSignature;
        newMessage.signingKey = message.signingKey;

        // Upflow or downflow.
        if (message.isDownflow()) {
            newMessage.flow = 'down';
        } else {
            newMessage.flow = 'up';
        }

        return newMessage;
    };


    /**
     * Gets the ephemeral private key (the own one).
     *
     * @method
     * @returns {string}
     */
    Greeting.prototype.getEphemeralPrivKey = function() {
        return this.askeMember.ephemeralPrivKey;
    };


    /**
     * Gets the ephemeral public key of a participant.
     *
     * @method
     * @param participantID {string}
     *     Participant ID to return. If left blank, one's own ephemeral public
     *     signing key is returned.
     * @returns {string}
     *     Ephemeral public signing key.
     */
    Greeting.prototype.getEphemeralPubKey = function(participantID) {
        if (participantID === undefined || participantID === this.id) {
            return this.askeMember.ephemeralPubKey;
        } else {
            if (this.askeMember.ephemeralPubKeys
                    && this.askeMember.ephemeralPubKeys.length > 0) {
                return this.askeMember.getMemberEphemeralPubKey(participantID);
            } else {
                return undefined;
            }
        }
    };


    /**
     * Returns the current ephemeral public keys.
     *
     * @method
     * @returns {array<string>}
     */
    Greeting.prototype.getEphemeralPubKeys = function() {
        return this.askeMember.ephemeralPubKeys;
    };


    /**
     * Returns the current group key.
     *
     * @method
     * @returns {string}
     */
    Greeting.prototype.getGroupKey = function() {
        return this.cliquesMember.groupKey;
    };


    return ns;
});
