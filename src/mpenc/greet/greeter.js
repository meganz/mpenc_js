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
    "mpenc/helper/utils",
    "mpenc/greet/cliques",
    "mpenc/greet/ske",
    "megalogger",
], function(assert, utils, cliques, ske, MegaLogger) {
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

    var logger = MegaLogger.getLogger('greeter', undefined, 'greet');

    // Message type bit mapping
    ns._AUX_BIT = 0;
    ns._DOWN_BIT = 1;
    ns._GKA_BIT = 2;
    ns._SKE_BIT = 3;
    ns._OP_BITS = 4;
    ns._INIT_BIT = 7;
    ns._RECOVER_BIT = 8;
    ns._OPERATION = { DATA: 0x00,
                      START: 0x01,
                      JOIN: 0x02,
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
     * @property PARTICIPANT_DATA {string}
     *     Data message.
     * @property INIT_INITIATOR_UP {string}
     *     Initiator initial upflow.
     * @property INIT_PARTICIPANT_UP {string}
     *     Participant initial upflow message.
     * @property INIT_PARTICIPANT_DOWN {string}
     *     Participant initial downflow.
     * @property INIT_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant initial subsequent downflow.
     * @property RECOVER_INIT_INITIATOR_UP {string}
     *     Initiator initial upflow for recovery.
     * @property RECOVER_INIT_PARTICIPANT_UP {string}
     *     Participant initial upflow message for recovery.
     * @property RECOVER_INIT_PARTICIPANT_DOWN {string}
     *     Participant initial downflow for recovery.
     * @property RECOVER_INIT_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant initial subsequent downflow for recovery.
     * @property JOIN_AUX_INITIATOR_UP {string}
     *     Initiator aux join upflow.
     * @property JOIN_AUX_PARTICIPANT_UP {string}
     *     Participant aux join upflow.
     * @property JOIN_AUX_PARTICIPANT_DOWN {string}
     *     Participant aux join downflow.
     * @property JOIN_AUX_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant aux join subsequent downflow.
     * @property EXCLUDE_AUX_INITIATOR_DOWN {string}
     *     Initiator aux exclude downflow.
     * @property EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant aux exclude subsequent.
     * @property RECOVER_EXCLUDE_AUX_INITIATOR_DOWN {string}
     *     Initiator aux exclude downflow for recovery.
     * @property RECOVER_EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN {string}
     *     Participant aux exclude subsequent for recovery.
     * @property REFRESH_AUX_INITIATOR_DOWN {string}
     *     Initiator aux refresh downflow.
     * @property REFRESH_AUX_PARTICIPANT_DOWN {string}
     *     Participant aux refresh downflow.
     * @property RECOVER_REFRESH_AUX_INITIATOR_DOWN {string}
     *     Initiator aux refresh downflow. for recovery
     * @property RECOVER_REFRESH_AUX_PARTICIPANT_DOWN {string}
     *     Participant aux refresh downflow for recovery.
     * @property QUIT_DOWN {string}
     *     Indicating departure. (Must be followed by an exclude sequence.)
     */
    ns.MESSAGE_TYPE = {
        // Data message.
        PARTICIPANT_DATA:                      '\u0000\u0000', // 0b00000000
        // Initial start sequence.
        INIT_INITIATOR_UP:                     '\u0000\u009c', // 0b10011100
        INIT_PARTICIPANT_UP:                   '\u0000\u001c', // 0b00011100
        INIT_PARTICIPANT_DOWN:                 '\u0000\u001e', // 0b00011110
        INIT_PARTICIPANT_CONFIRM_DOWN:         '\u0000\u001a', // 0b00011010
        RECOVER_INIT_INITIATOR_UP:             '\u0001\u009c', // 0b10011100
        RECOVER_INIT_PARTICIPANT_UP:           '\u0001\u001c', // 0b00011100
        RECOVER_INIT_PARTICIPANT_DOWN:         '\u0001\u001e', // 0b00011110
        RECOVER_INIT_PARTICIPANT_CONFIRM_DOWN: '\u0001\u001a', // 0b00011010
        // Join sequence.
        JOIN_AUX_INITIATOR_UP:                 '\u0000\u00ad', // 0b10101101
        JOIN_AUX_PARTICIPANT_UP:               '\u0000\u002d', // 0b00101101
        JOIN_AUX_PARTICIPANT_DOWN:             '\u0000\u002f', // 0b00101111
        JOIN_AUX_PARTICIPANT_CONFIRM_DOWN:     '\u0000\u002b', // 0b00101011
        // Exclude sequence.
        EXCLUDE_AUX_INITIATOR_DOWN:            '\u0000\u00bf', // 0b10111111
        EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN:  '\u0000\u003b', // 0b00111011
        RECOVER_EXCLUDE_AUX_INITIATOR_DOWN:    '\u0001\u00bf', // 0b10111111
        RECOVER_EXCLUDE_AUX_PARTICIPANT_CONFIRM_DOWN: '\u0001\u003b', // 0b00111011
        // Refresh sequence.
        REFRESH_AUX_INITIATOR_DOWN:            '\u0000\u00c7', // 0b11000111
        REFRESH_AUX_PARTICIPANT_DOWN:          '\u0000\u0047', // 0b01000111
        RECOVER_REFRESH_AUX_INITIATOR_DOWN:    '\u0001\u00c7', // 0b11000111
        RECOVER_REFRESH_AUX_PARTICIPANT_DOWN:  '\u0001\u0047', // 0b01000111
        // Quit indication.
        QUIT_DOWN:                             '\u0000\u00d3'  // 0b11010011
    };


    /** Mapping of message type to string representation. */
    ns.MESSAGE_TYPE_MAPPING = {};
    for (var propName in ns.MESSAGE_TYPE) {
        ns.MESSAGE_TYPE_MAPPING[ns.MESSAGE_TYPE[propName]] = propName;
    }


    /**
     * Converts a message type string to a number.
     *
     * @param typeString {string}
     * @return {integer}
     *     Number representing the message type.
     */
    ns.messageTypeToNumber = function(typeString) {
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
    ns.messageTypeFromNumber = function(typeNumber) {
        return String.fromCharCode(typeNumber >>> 8)
               + String.fromCharCode(typeNumber & 0xff);
    };


    // Checks whether a specific bit is set on a message type.
    function _isBitSetOnMessageType(messageType, bit) {
        if (typeof(messageType) === 'string') {
            messageType = ns.messageTypeToNumber(messageType);
        }
        return ((messageType & (1 << bit)) > 0);
    }


    /**
     * Inspects the AUX bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isAuxBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._AUX_BIT);
    };


    /**
     * Inspects the DOWN bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isDownBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._DOWN_BIT);
    };


    /**
     * Inspects the GKA bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isGkaBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._GKA_BIT);
    };


    /**
     * Inspects the SKE bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isSkeBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._SKE_BIT);
    };


    /**
     * Inspects the INIT bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isInitBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._INIT_BIT);
    };


    /**
     * Inspects the RECOVER bit of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {boolean}
     *     True if the bit is set, otherwise false.
     */
    ns.isRecoverBitOnMessageType = function(messageType) {
        return _isBitSetOnMessageType(messageType, ns._RECOVER_BIT);
    };


    /**
     * Inspects the OPERATION bits of the message type.
     *
     * @param {integer|string}
     *     Message type, either as a number or two character string.
     * @return {integer}
     *     Number of the operation.
     */
    ns.getOperationOnMessageType = function(messageType) {
        if (typeof(messageType) === 'string') {
            messageType = ns.messageTypeToNumber(messageType);
        }
        return (messageType & ns._OPERATION_MASK) >>> ns._OP_BITS;
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
     * Carries message content for the mpENC protocol flow and data messages.
     *
     * @constructor
     * @param source {string}
     *     Message originator (from).
     * @returns {mpenc.greet.greeter.ProtocolMessage}
     *
     * @property source {string|object}
     *     Message originator (from) or a {ProtocolMessage} object to copy.
     * @property dest {string}
     *     Message destination (to).
     * @property messageType {string}
     *     mpENC protocol message type, one of {mpenc.greet.greeter.MESSAGE_TYPE}.
     * @property sidkeyHint {string}
     *     One character string (a single byte), hinting at the right
     *     combination of session ID and group key used for a data message.
     * @property members {Array<string>}
     *     List (array) of all participating members.
     * @property intKeys {Array<string>}
     *     List (array) of intermediate keys for group key agreement.
     * @property debugKeys {Array<string>}
     *     List (array) of keying debugging strings.
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
    var ProtocolMessage = function(source) {
        if (source === undefined) {
            source = {};
        }
        if (source instanceof Object) {
            this.source = source.source || '';
        } else {
            this.source = source || '';
        }
        this.dest = source.dest || '';
        this.messageType = source.messageType || null;
        this.sidkeyHint = source.sidkeyHint || null;
        this.members = source.members || [];
        this.intKeys = source.intKeys || [];
        this.debugKeys = source.debugKeys || [];
        this.nonces = source.nonces || [];
        this.pubKeys = source.pubKeys || [];
        this.sessionSignature = source.sessionSignature || null;
        this.signingKey = source.signingKey || null;
        this.signature = source.signature || null;
        this.signatureOk = source.signatureOk || false;
        this.rawMessage = source.rawMessage || null;
        this.protocol = source.protocol || null;
        this.data = source.data || null;

        return this;
    };
    ns.ProtocolMessage = ProtocolMessage;


    /**
     * Returns a numeric representation of the message type.
     *
     * @method
     * @returns {integer}
     *     Message type as numeric value.
     */
    ProtocolMessage.prototype.getMessageTypeNumber = function() {
        return ns.messageTypeToNumber(this.messageType);
    };





    /**
     * Returns a string representation of the message type.
     *
     * @method
     * @returns {string}
     *     Message type as human readable string.
     */
    ProtocolMessage.prototype.getMessageTypeString = function() {
        return ns.MESSAGE_TYPE_MAPPING[this.messageType];
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
    ProtocolMessage.prototype._setBit= function(bit, value, noMessageCheck) {
        var newMessageTypeNum = this.getMessageTypeNumber();
        if (value === true || value === 1) {
            newMessageTypeNum |= 1 << bit;
        } else if (value === 0 || value === false) {
            newMessageTypeNum &= 0xffff - (1 << bit);
        } else {
            throw new Error("Illegal value for set/clear bit operation.");
        }
        var newMessageType = ns.messageTypeFromNumber(newMessageTypeNum);
        if (ns.MESSAGE_TYPE_MAPPING[newMessageType] === undefined) {
            if (noMessageCheck !== true && noMessageCheck !== 1) {
                throw new Error("Illegal message type!");
            } else {
                this.messageType = newMessageType;
                logger.debug('Arrived at an illegal message type, but was told to ignore it: '
                             + newMessageType);
            }
        } else {
            this.messageType = newMessageType;
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
    ProtocolMessage.prototype._readBit= function(bit) {
        return (_isBitSetOnMessageType(this.messageType, bit));
    };


    /**
     * Returns whether the message is for an auxiliary protocol flow.
     *
     * @method
     * @returns {bool}
     *     `true` for an auxiliary protocol flow.
     */
    ProtocolMessage.prototype.isAuxiliary = function() {
        return this._readBit(ns._AUX_BIT);
    };


    /**
     * Returns whether the message is for the downflow (broadcast).
     *
     * @method
     * @returns {bool}
     *     `true` for a downflow message.
     */
    ProtocolMessage.prototype.isDownflow = function() {
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
    ProtocolMessage.prototype.setDownflow = function(noMessageCheck) {
        return this._setBit(ns._DOWN_BIT, true, noMessageCheck);
    };


    /**
     * Returns whether the message is for the Group Key Agreement.
     *
     * @method
     * @returns {bool}
     *     `true` for a message containing GKA content.
     */
    ProtocolMessage.prototype.isGKA = function() {
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
    ProtocolMessage.prototype.clearGKA = function(noMessageCheck) {
        return this._setBit(ns._GKA_BIT, false, noMessageCheck);
    };


    /**
     * Returns whether the message is for the Signature Key Exchange.
     *
     * @method
     * @returns {bool}
     *     `true` for a message containing SKE content.
     */
    ProtocolMessage.prototype.isSKE = function() {
        return this._readBit(ns._SKE_BIT);
    };


    /**
     * Returns whether the message is from the protocol flow initiator.
     *
     * @method
     * @returns {bool}
     *     `true` for a message from the protocol flow initiator.
     */
    ProtocolMessage.prototype.isInitiator = function() {
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
    ProtocolMessage.prototype.clearInitiator = function(noMessageCheck) {
        return this._setBit(ns._INIT_BIT, false, noMessageCheck);
    };


    /**
     * Returns whether the message is for a recovery protocol flow.
     *
     * @method
     * @returns {bool}
     *     `true` for a message for a recovery flow.
     */
    ProtocolMessage.prototype.isRecover = function() {
        return this._readBit(ns._RECOVER_BIT);
    }


    /**
     * Returns the protocol operation of the message.
     *
     * @method
     * @returns {string}
     *     A clear text expression of the type of protocol operation.
     *     One of "DATA", "START", "JOIN", "EXCLUDE", "REFRESH" or "QUIT".
     */
    ProtocolMessage.prototype.getOperation = function() {
        return ns.OPERATION_MAPPING[(this.getMessageTypeNumber() & ns._OPERATION_MASK)
                                    >>> ns._OP_BITS];
    }


    /**
     * Implementation of a protocol handler with its state machine.
     *
     * @constructor
     * @param id {string}
     *     Member's identifier string.
     * @param privKey {string}
     *     This participant's static/long term private key.
     * @param pubKey {string}
     *     This participant's static/long term public key.
     * @param staticPubKeyDir {PubKeyDir}
     *     Public key directory object.
     * @param queueUpdatedCallback {Function}
     *      A callback function, that will be called every time something was
     *      added to `protocolOutQueue`, `messageOutQueue` or `uiQueue`.
     * @param stateUpdatedCallback {Function}
     *      A callback function, that will be called every time the `state` is
     *      changed.
     * @returns {GreetWrapper}
     *
     * @property id {string}
     *     Member's identifier string.
     * @property privKey {string}
     *     This participant's static/long term private key.
     * @property pubKey {string}
     *     This participant's static/long term public key.
     * @property staticPubKeyDir {object}
     *     An object with a `get(key)` method, returning the static public key of
     *     indicated by member ID `ky`.
     * @property askeMember {SignatureKeyExchangeMember}
     *      Reference to signature key exchange protocol handler with the same
     *      participant ID.
     * @property cliquesMember {CliquesMember}
     *     Reference to CLIQUES protocol handler with the same participant ID.
     * @property state {integer}
     *     Current state of the mpENC protocol handler according to {STATE}.
     * @property recovering {bool}
     *     `true` if in recovery mode state, usually `false`.
     */
    var GreetWrapper = function(id, privKey, pubKey, staticPubKeyDir) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.state = ns.STATE.NULL;
        this.recovering = false;

        // Sanity check.
        _assert(this.id && this.privKey && this.pubKey && this.staticPubKeyDir,
                'Constructor call missing required parameters.');

        // Make protocol handlers for sub tasks.
        this.cliquesMember = new cliques.CliquesMember(this.id);
        this.askeMember = new ske.SignatureKeyExchangeMember(this.id);
        this.askeMember.staticPrivKey = privKey;
        this.askeMember.staticPubKeyDir = staticPubKeyDir;

        return this;
    };
    ns.GreetWrapper = GreetWrapper;


    /**
     * Mechanism to start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     */
    GreetWrapper.prototype.start = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.messageType = ns.MESSAGE_TYPE.RECOVER_INIT_INITIATOR_UP;
        } else {
            protocolMessage.messageType = ns.MESSAGE_TYPE.INIT_INITIATOR_UP;
        }
        return protocolMessage;
    };


    /**
     * Mechanism to start a new upflow for joining new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     */
    GreetWrapper.prototype.join = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        protocolMessage.messageType = ns.MESSAGE_TYPE.JOIN_AUX_INITIATOR_UP;
        return protocolMessage;
    };


    /**
     * Mechanism to start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     */
    GreetWrapper.prototype.exclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.messageType = ns.MESSAGE_TYPE.RECOVER_EXCLUDE_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.messageType = ns.MESSAGE_TYPE.EXCLUDE_AUX_INITIATOR_DOWN;
        }

        // We need to update the session state.
        this.sessionId = this.askeMember.sessionId;
        this.members = this.askeMember.members;
        this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
        this.groupKey = this.cliquesMember.groupKey;

        return protocolMessage;
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    GreetWrapper.prototype.quit = function() {
        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();

        var protocolMessage = this._mergeMessages(null, askeMessage);
        protocolMessage.messageType = ns.MESSAGE_TYPE.QUIT_DOWN;
        return protocolMessage;
    };


    /**
     * Mechanism to refresh group key.
     *
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    GreetWrapper.prototype.refresh = function() {
        var cliquesMessage = this.cliquesMember.akaRefresh();

        var protocolMessage = this._mergeMessages(cliquesMessage, null);
        if (this.recovering) {
            protocolMessage.messageType = ns.MESSAGE_TYPE.RECOVER_REFRESH_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.messageType = ns.MESSAGE_TYPE.REFRESH_AUX_INITIATOR_DOWN;
        }
        // We need to update the group key.
        this.groupKey = this.cliquesMember.groupKey;
        return protocolMessage;
    };


    GreetWrapper.prototype.processIncoming = function(decodedMessage,
            quitCallback, readyCallback, errorCallback, pushCallback, stateUpdatedCallback) {
        var oldState = this.state;
        try {
            var keyingMessageResult = this._processMessage(decodedMessage);
            if (keyingMessageResult && keyingMessageResult.newState !== null) {
                if (keyingMessageResult.newState === ns.STATE.QUIT) {
                    quitCallback();
                } else if (keyingMessageResult.newState === ns.STATE.READY) {
                    readyCallback(this);
                }
            }
        } catch (e) {
            if (e.message.lastIndexOf('Session authentication by member') === 0) {
                errorCallback(e);
                return;
            } else {
                throw e;
            }
        }
        if (keyingMessageResult === null) {
            return;
        }
        var outContent = keyingMessageResult.decodedMessage;

        if (outContent) {
            pushCallback(outContent);
        } else {
            // Nothing to do, we're done here.
            // TODO(gk): xl: does this mean we should actually break here?
        }
        if (keyingMessageResult.newState &&
                (keyingMessageResult.newState !== oldState)) {
            // Update the state if required.
            logger.debug('Reached new state: '
                         + ns.STATE_MAPPING[keyingMessageResult.newState]);
            stateUpdatedCallback(keyingMessageResult.newState);
        }
    };

    /**
     * Handles greet (key agreement) protocol execution with all participants.
     *
     * @method
     * @param message {ProtocolMessage}
     *     Received message (decoded). See {@link ProtocolMessage}.
     * @returns {object}
     *     Object containing the decoded message content as
     *     {ProtocolMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the GreetWrapper state in
     *     attribute `newState`.
     */
    GreetWrapper.prototype._processMessage = function(message) {
        logger.debug('Processing message of type '
                     + message.getMessageTypeString());
        if (this.state === ns.STATE.QUIT) {
            // We're not par of this session, get out of here.
            logger.debug("Ignoring message as we're in state QUIT.");
            return null;
        }

        // If I'm not part of it any more, go and quit.
        if (message.members && (message.members.length > 0)
                && (message.members.indexOf(this.id) === -1)) {
            if (this.state !== ns.STATE.QUIT) {
                this.state = ns.STATE.QUIT;
                return { decodedMessage: null,
                         newState: this.state };
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
        if (message.isRecover()) {
            // We're getting this message as part of a recovery flow.
            this.recovering = true;
            // In case of an upflow, we must also discard session authentications.
            if (!message.isDownflow()) {
                this.askeMember.discardAuthentications();
            }
        }

        var inCliquesMessage = this._getCliquesMessage(message);
        var inAskeMessage = this._getAskeMessage(message);
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;
        var newState = null;

        // Three cases: QUIT, upflow or downflow message.
        if (message.messageType === ns.MESSAGE_TYPE.QUIT_DOWN) {
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
                outMessage.messageType = message.messageType;
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
            outMessage.messageType = message.messageType;
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
            this.recovering = false;
        }

        if (outMessage) {
            logger.debug('Sending message of type '
                         + outMessage.getMessageTypeString());
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
     * @returns {ProtocolMessage}
     *     Joined message (not wire encoded).
     */
    GreetWrapper.prototype._mergeMessages = function(cliquesMessage,
                                                           askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = new ns.ProtocolMessage(this.id);

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
        newMessage.debugKeys = cliquesMessage.debugKeys || null;
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
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.cliques.CliquesMessage}
     *     Extracted message.
     */
    GreetWrapper.prototype._getCliquesMessage = function(message) {
        var newMessage = cliques.CliquesMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.members = message.members;
        newMessage.intKeys = message.intKeys;
        newMessage.debugKeys = message.debugKeys;

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
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    GreetWrapper.prototype._getAskeMessage = function(message) {
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
    GreetWrapper.prototype.getEphemeralPrivKey = function() {
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
    GreetWrapper.prototype.getEphemeralPubKey = function(participantID) {
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
    GreetWrapper.prototype.isSessionAcknowledged = function(participantID) {
        return this.askeMember.isSessionAcknowledged();
    };


    /**
     * Discard all authentications, and set only self to authenticated.
     *
     * @method
     */
    GreetWrapper.prototype.discardAuthentications = function() {
        this.askeMember.discardAuthentications();
    };


    /**
     * Returns the current session ID.
     *
     * @method
     * @returns {string}
     */
    GreetWrapper.prototype.getSessionId = function() {
        return this.askeMember.sessionId;
    };


    /**
     * Returns the current members.
     *
     * @method
     * @returns {array<string>}
     */
    GreetWrapper.prototype.getMembers = function() {
        return this.askeMember.members;
    };


    /**
     * Returns the current ephemeral public keys.
     *
     * @method
     * @returns {array<string>}
     */
    GreetWrapper.prototype.getEphemeralPubKeys = function() {
        return this.askeMember.ephemeralPubKeys;
    };


    /**
     * Returns the current group key.
     *
     * @method
     * @returns {string}
     */
    GreetWrapper.prototype.getGroupKey = function() {
        return this.cliquesMember.groupKey;
    };



    return ns;
});
