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
    "mpenc/helper/utils",
    "mpenc/greet/cliques",
    "mpenc/greet/ske",
    "mpenc/codec",
    "megalogger",
], function(assert, async, utils, cliques, ske, codec, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/greet/greet
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

    var logger = MegaLogger.getLogger('greeter', undefined, 'greet');


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
     * @property REFRESH_AUX_PARTICIPANT_DOWN {string}
     *     Participant aux refresh downflow.
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
        REFRESH_AUX_PARTICIPANT_DOWN:          '\u0000\u0047', // 0b01000111
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
     * @param source {string}
     *     Message originator (from).
     * @returns {mpenc.greet.greeter.GreetMessage}
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
    var GreetMessage = function(source) {
        if (source === undefined) {
            source = {};
        }
        if (source instanceof Object) {
            this.source = source.source || '';
        } else {
            this.source = source || '';
        }
        this.dest = source.dest || '';
        this.greetType = source.greetType || null;
        this.sidkeyHint = source.sidkeyHint || null;
        this.members = source.members || [];
        this.intKeys = source.intKeys || [];
        this.nonces = source.nonces || [];
        this.pubKeys = source.pubKeys || [];
        this.sessionSignature = source.sessionSignature || null;
        this.signingKey = source.signingKey || null;
        this.signature = source.signature || null;
        this.signatureOk = source.signatureOk || false;
        this.rawMessage = source.rawMessage || null;
        this.data = source.data || null;

        return this;
    };
    ns.GreetMessage = GreetMessage;


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
     * @method
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
     * @method
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
        if (!message) {
            return null;
        }

        // TODO(gk): high-priority - put range checks etc on the below
        var out = new ns.GreetMessage();
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


    /**
     * @description SessionStore holds all of the public and private data required to
     * restore a greet object to a given state.
     *
     * @constructor
     * @param id {string}
     *      The id for <b>this</b> member.
     * @param privKey
     *      The static private key for <b>this</b> member.
     * @param pubKey
     *      The static public key for <b>this</b> member.
     * @param staticPubKeyDir
     *      Callback to obtain public keys for <b>other</b> memebrs.
     * @property state {?number}
     *      The state of the last Greeting.
     * @property members {?array<string>}
     *      The members for the greet session.
     *
     * @property sessionId {?string}
     *      The id for the session.
     * @property ephemeralPrivKey {?string}
     *      The ephemeral private key for <b>this</b> member.
     * @property ephemeralPubKey {?string}
     *      The ephemeral public key for <b>this</b> member.
     * @property nonce {?string}
     *      The nonce for <b>this</b> member.
     * @property ephemeralPubKeys {?array<string>}
     *      The ephemeral signing keys for the other members in the chat session.
     * @property nonces {?array<string>}
     *      The nonces for the other members in the chat session.
     *
     * @property groupKey {?string}
     *      The group secret key for this session.
     * @property privKeyList {?array<string>}
     *      The list of private contributions for <b>this</b> member.
     * @property intKeys {?array<string>}
     *      The list of previous initial keys for all members.
     */
    var GreetStore = function(id, privKey, pubKey, staticPubKeyDir, state, members,
            sessionId, ephemeralPrivKey, ephemeralPubKey, nonce, ephemeralPubKeys, nonces,
            groupKey, privKeyList, intKeys) {
        _assert(id && privKey && pubKey && staticPubKeyDir,
                'Constructor call missing required parameters.');

        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.state = state || ns.STATE.NULL;
        this.members = utils.clone(members) || [];
        _assert(this.state === ns.STATE.READY || this.state === ns.STATE.NULL,
            "tried to create a GreetStore on a state other than NULL or READY.");

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

        return this;
    };

    ns.GreetStore = GreetStore;


    /**
     * Implementation of a protocol handler with its state machine.
     *
     * @constructor
     * @param store {module:mpenc/greet/greeter.GreetStore}
     *      GreetStore
     * @param stateUpdatedCallback {Function}
     *      A callback function, that will be called every time the `state` is
     *      changed.
     * @returns {Greeting}
     */
    var Greeting = function(store, stateUpdatedCallback) {
        this.id = store.id;
        this.privKey = store.privKey;
        this.pubKey = store.pubKey;
        this.staticPubKeyDir = store.staticPubKeyDir;

        this.state = store.state;
        this.stateUpdatedCallback = stateUpdatedCallback || function() {};
        this._send = new async.Observable(true);

        var cliquesMember = new cliques.CliquesMember(store.id);
        cliquesMember.members = utils.clone(store.members);
        cliquesMember.groupKey = utils.clone(store.groupKey);
        cliquesMember.privKeyList = utils.clone(store.privKeyList);
        cliquesMember.intKeys = utils.clone(store.intKeys);
        this.cliquesMember = cliquesMember;

        var askeMember = new ske.SignatureKeyExchangeMember(store.id);
        askeMember.staticPrivKey = store.privKey;
        askeMember.staticPubKeyDir = store.staticPubKeyDir;
        askeMember.sessionId = store.sessionId;
        askeMember.members = utils.clone(store.members);
        askeMember.ephemeralPrivKey = utils.clone(store.ephemeralPrivKey);
        askeMember.ephemeralPubKey = utils.clone(store.ephemeralPubKey);
        askeMember.nonce = utils.clone(store.nonce);
        askeMember.ephemeralPubKeys = utils.clone(store.ephemeralPubKeys);
        askeMember.nonces = utils.clone(store.nonces);
        askeMember.authenticatedMembers = [];
        this.askeMember = askeMember;

        return this;
    };
    ns.Greeting = Greeting;

    Greeting.prototype._updateState = function(state) {
        // Update the state if required.
        _assert(typeof state === "number");
        logger.debug('Reached new state: ' + ns.STATE_MAPPING[state]);
        this.state = state;
        this.stateUpdatedCallback(this);
    };

    Greeting.prototype._assertState = function(valid, message) {
        _assert(valid.some(function(v) {
            return this.state === v;
        }, this), message);
    };

    Greeting.prototype._encodeAndPublish = function(packet, state) {
        _assert(packet);
        var payload = ns.encodeGreetMessage(
            packet,
            this.getEphemeralPrivKey(),
            this.getEphemeralPubKey());
        // TODO(xl): use a RawSendT instead of Array[2]
        this._send.publish([packet.dest, payload]);
        if (state !== undefined) {
            this._updateState(state);
        }
    };

    Greeting.prototype.subscribeSend = function(subscriber) {
        return this._send.subscribe(subscriber);
    };

    /**
     * Create a new GreetStore from this greeting.
     *
     * The state must be READY or NULL.
     *
     * @method
     */
    Greeting.prototype.toGreetStore = function() {
        return new ns.GreetStore(this.id, this.privKey, this.pubKey, this.staticPubKeyDir,
            this.state, this.askeMember.members, this.askeMember.sessionId,
            this.askeMember.ephemeralPrivKey, this.askeMember.ephemeralPubKey, this.askeMember.nonce,
            this.askeMember.ephemeralPubKeys, this.askeMember.nonces,
            this.cliquesMember.groupKey, this.cliquesMember.privKeyList, this.cliquesMember.intKeys);
    };

    /**
     * Mechanism to start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     */
    Greeting.prototype.start = function(otherMembers) {
        this._assertState([ns.STATE.NULL],
                'start() can only be called from an uninitialised state.');
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        var packet = this._mergeMessages(cliquesMessage, askeMessage);
        packet.greetType = ns.GREET_TYPE.INIT_INITIATOR_UP;

        if (packet.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
        } else {
            this._encodeAndPublish(packet, ns.STATE.INIT_UPFLOW);
        }
    };


    /**
     * Mechanism to start a new upflow for including new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to include into the group.
     */
    Greeting.prototype.include = function(newMembers) {
        this._assertState([ns.STATE.READY],
                'include() can only be called from a ready state.');
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        var packet = this._mergeMessages(cliquesMessage, askeMessage);
        packet.greetType = ns.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP;
        this._encodeAndPublish(packet, ns.STATE.AUX_UPFLOW);
    };


    /**
     * Mechanism to start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     */
    Greeting.prototype.exclude = function(excludeMembers) {
        this._assertState([ns.STATE.READY],
                'exclude() can only be called from a ready state.');
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        var packet = this._mergeMessages(cliquesMessage, askeMessage);
        packet.greetType = ns.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN;

        // We need to update the session state.
        this.sessionId = this.askeMember.sessionId;
        this.members = this.askeMember.members;
        this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
        this.groupKey = this.cliquesMember.groupKey;

        if (packet.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
        } else {
            var newState = this.isSessionAcknowledged() ? ns.STATE.READY : ns.STATE.AUX_DOWNFLOW;
            this._encodeAndPublish(packet, newState);
        }
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @method
     */
    Greeting.prototype.quit = function() {
        if (this.state === ns.STATE.QUIT) {
            return; // Nothing do do here.
        }

        _assert(this.getEphemeralPrivKey() !== null,
                'Not participating.');

        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();

        var packet = this._mergeMessages(null, askeMessage);
        packet.greetType = ns.GREET_TYPE.QUIT_DOWN;
        this._encodeAndPublish(packet, ns.STATE.QUIT);
    };


    /**
     * Mechanism to refresh group key.
     *
     * @method
     */
    Greeting.prototype.refresh = function() {
        this._assertState([ns.STATE.READY, ns.STATE.INIT_DOWNFLOW, ns.STATE.AUX_DOWNFLOW],
                'refresh() can only be called from a ready or downflow states.');
        var cliquesMessage = this.cliquesMember.akaRefresh();

        var packet = this._mergeMessages(cliquesMessage, null);
        packet.greetType = ns.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN;
        // We need to update the group key.
        this.groupKey = this.cliquesMember.groupKey;
        this._encodeAndPublish(packet, ns.STATE.READY);
    };


    Greeting.prototype.processIncoming = function(from, content) {
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
        var oldState = this.state;
        var result = this._processMessage(decodedMessage);
        if (result === null) {
            return;
        }
        if (result.decodedMessage) {
            this._encodeAndPublish(result.decodedMessage);
        }
        if (result.newState) {
            this._updateState(result.newState);
        }
        return result.newState;
    };

    /**
     * Handles greet (key agreement) protocol execution with all participants.
     *
     * @method
     * @param message {GreetMessage}
     *     Received message (decoded).
     * @returns {object}
     *     Object containing the decoded message content as
     *     {GreetMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the Greeting state in
     *     attribute `newState`.
     */
    Greeting.prototype._processMessage = function(message) {
        logger.debug('Processing message of type '
                     + message.getGreetTypeString());
        if (this.state === ns.STATE.QUIT) {
            // We're not par of this session, get out of here.
            logger.debug("Ignoring message as we're in state QUIT.");
            return null;
        }

        // If I'm not part of it any more, go and quit.
        if (message.members && (message.members.length > 0)
                && (message.members.indexOf(this.id) === -1)) {
            if (this.state !== ns.STATE.QUIT) {
                return { decodedMessage: null,
                         newState: ns.STATE.QUIT };
            } else {
                return null;
            }
        }

        // Ignore the message if it is not for me.
        if ((message.dest !== '') && (message.dest !== this.id)) {
            return null;
        }

        // Ignore the message if it is from me.
        if (message.source === this.id) {
            return null;
        }

        // State transitions.
        var inCliquesMessage = this._getCliquesMessage(message);
        var inAskeMessage = this._getAskeMessage(message);
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;
        var newState = null;

        // Three cases: QUIT, upflow or downflow message.
        if (message.greetType === ns.GREET_TYPE.QUIT_DOWN) {
            // QUIT message.
            _assert(message.signingKey,
                    'Inconsistent message content with message type (signingKey).');
            // Sender is quitting participation.
            this.askeMember.oldEphemeralKeys[message.source] = {
                    priv: message.signingKey,
                    pub:  this.askeMember.ephemeralPubKeys[message.source]
            };
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

        if (this.askeMember.isSessionAcknowledged()) {
            // We have seen and verified all broadcasts from others.
            // Let's update our state information.
            newState = ns.STATE.READY;
            this.sessionId = this.askeMember.sessionId;
            this.members = this.askeMember.members;
            this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
            this.groupKey = this.cliquesMember.groupKey;
            logger.debug('Reached READY state.');
        }

        if (outMessage) {
            logger.debug('Sending message of type '
                         + outMessage.getGreetTypeString());
        } else {
            logger.debug('No message to send.');
        }
        return { decodedMessage: outMessage,
                 newState: newState };
    };


    /**
     * Merges the contents of the messages for ASKE and CLIQUES into one message.
     *
     * @method
     * @param cliquesMessage {mpenc.greet.cliques.CliquesMessage}
     *     Message from CLIQUES protocol workflow.
     * @param askeMessage {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Message from ASKE protocol workflow.
     * @returns {GreetMessage}
     *     Joined message (not wire encoded).
     */
    Greeting.prototype._mergeMessages = function(cliquesMessage,
                                                           askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = new ns.GreetMessage(this.id);

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
     * @method
     * @param message {GreetMessage}
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
     * @method
     * @param message {GreetMessage}
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
     * Returns true if the authenticated signature key exchange is fully
     * acknowledged.
     *
     * @method
     * @returns {boolean}
     *     True on a valid session.
     */
    Greeting.prototype.isSessionAcknowledged = function(participantID) {
        return this.askeMember.isSessionAcknowledged();
    };


    /**
     * Discard all authentications, and set only self to authenticated.
     *
     * @method
     */
    Greeting.prototype.discardAuthentications = function() {
        this.askeMember.discardAuthentications();
    };


    /**
     * Returns the current session ID.
     *
     * @method
     * @returns {string}
     */
    Greeting.prototype.getSessionId = function() {
        return this.askeMember.sessionId;
    };


    /**
     * Returns the current members.
     *
     * @method
     * @returns {array<string>}
     */
    Greeting.prototype.getMembers = function() {
        return this.askeMember.members;
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
