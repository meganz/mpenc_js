/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/version",
    "mpenc/greet/greeter",
    "asmcrypto",
    "jodid25519",
    "megalogger",
], function(assert, utils, version, greeter, asmCrypto, jodid25519, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/codec
     * Implementation of a protocol encoder/decoder.
     *
     * @description
     * <p>Implementation of a protocol encoder/decoder.</p>
     *
     * <p>
     * The implementation is finally aiming to mock the binary encoding scheme
     * as used by OTR. But initially it will use a somewhat JSON-like
     * intermediate.</p>
     */
    var ns = {};

    var _assert = assert.assert;

    var _PROTOCOL_INDICATOR = 'mpENC';
    var _PROTOCOL_PREFIX = '?' + _PROTOCOL_INDICATOR;

    var logger = MegaLogger.getLogger('codec', undefined, 'mpenc');

    /**
     * Carries information extracted from a received mpENC protocol message for
     * the greet protocol (key exchange and agreement).
     *
     * @constructor
     * @returns {mpenc.codec.ProtocolMessageInfo}
     *
     * @property protocolVersion {integer}
     *     mpENC protocol version number.
     * @property sidkeyHint {string}
     *     Hints at the right combination of session ID and group key used for
     *     a data message.
     * @property sidkeyHintNumber {integer}
     *     Hints at the right combination of session ID and group key used for
     *     a data message.
     * @property messageType {string}
     *     Raw mpENC protocol message type, one of {mpenc.greet.greeter.MESSAGE_TYPE}.
     * @property messageTypeNumber {integer}
     *     mpENC protocol message type as number, one of
     *     {mpenc.greet.greeter.MESSAGE_TYPE}.
     * @property messageTypeString {string}
     *     Corresponding mpENC protocol message type indicator as a string.
     * @property from {string}
     *     Message originator's participant ID.
     * @property to {string}
     *     Message destination's participant ID.
     * @property operation {string}
     *     A clear text expression of the type of protocol operation.
     *     One of "DATA", "START", "JOIN", "EXCLUDE", "REFRESH" or "QUIT".
     * @property messageSignature {string}
     *     Signature of message.
     * @property signedContent {string}
     *     Raw content signed by signature.
     * @property origin {string}
     *     Indicates whether the message originated from the "initiator" of a
     *     protocol operation or from a "participant". If the originator is
     *     not a member, the value will be "outsider". The value will be "???"
     *     if no members list is part of the message (participation has to be
     *     determined using the members in the handler).
     * @property agreement {string}
     *     "initial" or "auxiliary" key agreement.
     * @property recover {bool}
     *     Indicates whether the message is part of a recovery (true) or normal
     *     protocol flow (false).
     * @property flow {string}
     *     "up" (directed message) or "down" (broadcast).
     * @property members {Array}
     *     List of group members' IDs enclosed.
     * @property numNonces {integer}
     *     Number of nonces enclosed.
     * @property numPubKeys {integer}
     *     Number of public signing keys enclosed.
     * @property numIntKeys {integer}
     *     Number of intermediate GDH keys enclosed.
     */
    var ProtocolMessageInfo = function() {
        this.protocolVersion = null;
        this.sidkeyHint = null;
        this.sidkeyHintNumber = null;
        this.messageType = null;
        this.messageTypeNumber = null;
        this.messageTypeString = null;
        this.from = null;
        this.to = null;
        this.messageSignature = null;
        this.signedContent = null;
        this.origin = null;
        this.operation = null;
        this.agreement = null;
        this.recover = false;
        this.flow = null;
        this.members = [];
        this.numNonces = 0;
        this.numPubKeys = 0;
        this.numIntKeys = 0;

        return this;
    };
    ns.ProtocolMessageInfo = ProtocolMessageInfo;


    /**
     * Returns whether the message is from the protocol flow initiator.
     *
     * @method
     * @returns {bool}
     *     `true` for a message from the protocol flow initiator.
     */
    ProtocolMessageInfo.prototype.isInitiator = function() {
        return (this.messageType & (1 << ns._INIT_BIT) > 0);
    }

    /**
     * "Enumeration" protocol message category types.
     *
     * @property PLAIN {integer}
     *     Plain text message (not using mpENC).
     * @property MPENC_QUERY {integer}
     *     Query to initiate an mpENC session.
     * @property MPENC_GREET_MESSAGE {integer}
     *     mpENC greet message.
     * @property MPENC_DATA_MESSAGE {integer}
     *     mpENC data message.
     * @property MPENC_ERROR {integer}
     *     Message for error in mpENC protocol.
     */
    ns.MESSAGE_CATEGORY = {
        PLAIN:               0x00,
        MPENC_QUERY:         0x01,
        MPENC_GREET_MESSAGE: 0x02,
        MPENC_DATA_MESSAGE:  0x03,
        MPENC_ERROR:         0x04,
    };


    // Add reverse mapping to string representation.
    var _MESSAGE_CATEGORY_MAPPING = {};
    for (var propName in ns.MESSAGE_CATEGORY) {
        _MESSAGE_CATEGORY_MAPPING[ns.MESSAGE_CATEGORY[propName]] = propName;
    }


    // "Magic numbers" used for prepending the data for the purpose of signing.
    var _MAGIC_NUMBERS = {};
    _MAGIC_NUMBERS[ns.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE] = 'greetmsgsig';
    _MAGIC_NUMBERS[ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE] = 'datamsgsig';
    _MAGIC_NUMBERS[ns.MESSAGE_CATEGORY.MPENC_ERROR] = 'errormsgsig';


    /**
     * "Enumeration" for TLV record types.
     *
     * @property PADDING {integer}
     *     Can be used for arbitrary length of padding byte sequences.
     * @property PROTOCOL_VERSION {integer}
     *     Indicates the protocol version to be used as a 16-bit unsigned integer.
     * @property DATA_MESSAGE {string}
     *     Data payload (chat message) content of the message.
     * @property MESSAGE_SIGNATURE {string}
     *     Signature of the entire message sent (must be the first TLV sent,
     *     and sign *all* remaining binary content).
     * @property MESSAGE_IV {string}
     *     Random initialisation vector for encrypted message payload.
     * @property MESSAGE_TYPE {integer}
     *     mpENC protocol message type. See `MESSAGE_TYPE`.
     * @property SIDKEY_HINT {integer}
     *     Hints at the right combination of session ID and group key used for
     *     a data message.
     * @property SOURCE {integer}
     *     Message originator ("from", must be only one).
     * @property DEST {integer}
     *     Message destination ("to", should be only one, broadcast if not
     *     present or empty).
     * @property MEMBER {integer}
     *     A participating member's ID.
     * @property INT_KEY {integer}
     *     An intermediate key for the group key agreement (max. occurrence is
     *     the number of members present).
     * @property NONCE {integer}
     *     A nonce of a member for ASKE (max. occurrence is the number of
     *     members present).
     * @property PUB_KEY {integer}
     *     Ephemeral public signing key of a member (max. occurrence is the
     *     number of members present).
     * @property SESSION_SIGNATURE {integer}
     *     Session acknowledgement signature using sender's static key.
     * @property SIGNING_KEY {integer}
     *     Session's ephemeral (private) signing key, published upon departing
     *     from a chat.
     */
    ns.TLV_TYPE = {
        PADDING:           0x0000,
        PROTOCOL_VERSION:  0x0001,
        DATA_MESSAGE:      0x0002,
        MESSAGE_SIGNATURE: 0x0003,
        MESSAGE_IV:        0x0004,
        MESSAGE_TYPE:      0x0005,
        SIDKEY_HINT:       0x0006,
        SOURCE:            0x0100, // 256
        DEST:              0x0101, // 257
        MEMBER:            0x0102, // 258
        INT_KEY:           0x0103, // 259
        NONCE:             0x0104, // 260
        PUB_KEY:           0x0105, // 261
        SESSION_SIGNATURE: 0x0106, // 262
        SIGNING_KEY:       0x0107, // 263
    };


    /**
     * Decodes a given binary TVL string to a type and value.
     *
     * @param tlv {string}
     *     A binary TLV string.
     * @returns {Object}
     *     An object containing the type of string (in `type`, 16-bit unsigned
     *     integer) and the value (in `value`, binary string of the pay load).
     *     left over bytes from the input are returned in `rest`.
     */
    ns.decodeTLV = function(tlv) {
        var type = ns._bin2short(tlv.substring(0, 2));
        var length = ns._bin2short(tlv.substring(2, 4));
        var value = tlv.substring(4, 4 + length);
        _assert(length === value.length,
                'TLV payload length does not match indicated length.');
        if (length === 0) {
            value = '';
        }
        return {
            type: type,
            value: value,
            rest: tlv.substring(length + 4)
        };
    };


    var _decodeMessageTLVs = function(message, pubKey, sessionID, groupKey) {
        if (!message) {
            return null;
        }

        var out = new greeter.ProtocolMessage();
        var debugOutput = [];

        while (message.length > 0) {
            var tlv = ns.decodeTLV(message);
            switch (tlv.type) {
                case ns.TLV_TYPE.PADDING:
                    // Completely ignore this.
                    debugOutput.push('padding: ' + tlv.value.length);
                    break;
                case ns.TLV_TYPE.PROTOCOL_VERSION:
                    out.protocol = tlv.value;
                    debugOutput.push('protocol: ' + tlv.value.charCodeAt(0));
                    break;
                case ns.TLV_TYPE.SOURCE:
                    out.source = tlv.value;
                    debugOutput.push('from: ' + tlv.value);
                    break;
                case ns.TLV_TYPE.DEST:
                    out.dest = tlv.value;
                    debugOutput.push('to: ' + tlv.value);
                    break;
                case ns.TLV_TYPE.MESSAGE_TYPE:
                    out.messageType = tlv.value;
                    debugOutput.push('messageType: 0x'
                                     + out.getMessageTypeNumber().toString(16)
                                     + ' (' + out.getMessageTypeString() + ')');
                    break;
                case ns.TLV_TYPE.MEMBER:
                    out.members.push(tlv.value);
                    debugOutput.push('member: ' + tlv.value);
                    break;
                case ns.TLV_TYPE.INT_KEY:
                    out.intKeys.push(tlv.value);
                    debugOutput.push('intKey: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.NONCE:
                    out.nonces.push(tlv.value);
                    debugOutput.push('nonce: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.PUB_KEY:
                    out.pubKeys.push(tlv.value);
                    debugOutput.push('pubKey: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.SESSION_SIGNATURE:
                    out.sessionSignature = tlv.value;
                    debugOutput.push('sessionSignature: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.SIGNING_KEY:
                    out.signingKey = tlv.value;
                    debugOutput.push('signingKey: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.MESSAGE_SIGNATURE:
                    out.signature = tlv.value;
                    out.rawMessage = tlv.rest;
                    debugOutput.push('messageSignature: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.MESSAGE_IV:
                    out.iv = tlv.value;
                    debugOutput.push('messageIV: ' + btoa(tlv.value));
                    break;
                case ns.TLV_TYPE.SIDKEY_HINT:
                    out.sidkeyHint = tlv.value;
                    debugOutput.push('sidkeyHint: 0x'
                                     + tlv.value.charCodeAt(0).toString(16));
                    break;
                case ns.TLV_TYPE.DATA_MESSAGE:
                    out.data = tlv.value;
                    debugOutput.push('rawDataMessage: ' + btoa(out.data));
                    break;
                default:
                    _assert(false, 'Received unknown TLV type: ' + tlv.type);
                    break;
            }

            message = tlv.rest;
        }

        _assert(out.protocol === version.PROTOCOL_VERSION,
                'Received wrong protocol version: ' + out.protocol.charCodeAt(0) + '.');
        // Debugging output.
        logger.debug('mpENC decoded message debug: ', debugOutput);

        return out;
    };


    /**
     * Decodes a given TLV encoded Greet message into an object.
     *
     * @param message {string}
     *     A binary message representation.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param sessionID {string}
     *     Session ID.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @returns {mpenc.greeter.greet.ProtocolMessage}
     *     Message as JavaScript object.
     */
    ns.decodeGreetMessage = function(message, pubKey, sessionID, groupKey) {
        var out = _decodeMessageTLVs(message, pubKey, sessionID, groupKey);

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
                out.signatureOk = ns.verifyMessageSignature(ns.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
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


    /**
     * Decodes a given TLV encoded data message into an object.
     *
     * @param message {string}
     *     A binary message representation.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param sessionID {string}
     *     Session ID.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @returns {mpenc.greeter.greet.ProtocolMessage}
     *     Message as JavaScript object.
     */
    ns.decodeDataMessage = function(message, pubKey, sessionID, groupKey) {
        var out = _decodeMessageTLVs(message, pubKey, sessionID, groupKey);

        // Some specifics depending on the type of mpENC message.
        var sidkeyHash = '';
        _assert(out.data);
        // Checking of session/group key.
        sidkeyHash = utils.sha256(sessionID + groupKey);
        _assert(out.sidkeyHint === sidkeyHash[0],
                'Session ID/group key hint mismatch.');

        // Some further crypto processing on data messages.
        out.data = ns.decryptDataMessage(out.data, groupKey, out.iv);
        logger.debug('mpENC decrypted data message debug: ', out.data);

        // Data message signatures are verified through trial decryption.
        return out;
    };

    /**
     * Inspects a given TLV encoded protocol message to extract information
     * on the message type.
     *
     * @param message {string}
     *     A binary message representation.
     * @param shallow {boolean}
     *     If true, only a "shallow" inspection will be performed, extracting
     *     (if present) `SIDKEY_HINT`, `MESSAGE_SIGNATURE`, raw signed data
     *     content, `PROTOCOL_VERSION` and `MESSAGE_TYPE`, ignoring all other
     *     TLV records.
     * @returns {ProtocolMessageInfo}
     *     Message meta-data.
     */
    ns.inspectMessageContent = function(message, shallow) {
        if (!message) {
            return null;
        }
        shallow = shallow || false;
        var out = new ProtocolMessageInfo();

        while (message.length > 0) {
            var tlv = ns.decodeTLV(message);
            switch (tlv.type) {
                case ns.TLV_TYPE.PROTOCOL_VERSION:
                    out.protocolVersion = tlv.value.charCodeAt(0);
                    break;
                case ns.TLV_TYPE.SIDKEY_HINT:
                    out.sidkeyHint = tlv.value;
                    out.sidkeyHintNumber = tlv.value.charCodeAt(tlv.value);
                    break;
                case ns.TLV_TYPE.SOURCE:
                    if (!shallow) {
                        out.from = tlv.value;
                    }
                    break;
                case ns.TLV_TYPE.DEST:
                    if (!shallow) {
                        out.to = tlv.value || '';
                    }
                    break;
                case ns.TLV_TYPE.MESSAGE_TYPE:
                    out.messageType = tlv.value;
                    out.messageTypeNumber = (tlv.value.charCodeAt(0) << 8)
                                             | tlv.value.charCodeAt(1);
                    out.messageTypeString = greeter.MESSAGE_TYPE_MAPPING[tlv.value];
                    break;
                case ns.TLV_TYPE.MESSAGE_SIGNATURE:
                    out.messageSignature = tlv.value;
                    out.signedContent = tlv.rest;
                    break;
                case ns.TLV_TYPE.MEMBER:
                    if (!shallow) {
                        out.members.push(tlv.value);
                    }
                    break;
                case ns.TLV_TYPE.NONCE:
                    if (!shallow) {
                        out.numNonces++;
                    }
                    break;
                case ns.TLV_TYPE.INT_KEY:
                    if (!shallow) {
                        out.numIntKeys++;
                    }
                    break;
                case ns.TLV_TYPE.PUB_KEY:
                    if (!shallow) {
                        out.numPubKeys++;
                    }
                    break;
                default:
                    // Ignoring all others.
                    break;
            }

            message = tlv.rest;
        }

        if (!shallow) {
            // Complete some details of the message.
            if (out.messageType !== null
                    && out.messageTypeString !== 'PARTICIPANT_DATA') {
                // Auxiliary vs. initial agreement.
                if (greeter.isAuxBitOnMessageType(out.messageTypeNumber)) {
                    out.agreement = 'auxiliary';
                } else {
                    out.agreement = 'initial';
                }

                // Upflow or downflow.
                if (greeter.isDownBitOnMessageType(out.messageTypeNumber)) {
                    out.flow = 'down';
                } else {
                    out.flow = 'up';
                }

                // Group Key Agreement.
                if (greeter.isGkaBitOnMessageType(out.messageTypeNumber)) {
                    out.agreement += ', GKA';
                }

                // Signature Key Exchange.
                if (greeter.isSkeBitOnMessageType(out.messageTypeNumber)) {
                    out.agreement += ', SKE';
                }

                // Operation.
                out.operation = greeter.OPERATION_MAPPING[
                        greeter.getOperationOnMessageType(out.messageTypeNumber)];

                // Initiator or participant.
                if (greeter.isInitBitOnMessageType(out.messageTypeNumber)) {
                    out.origin = 'initiator';
                } else {
                    out.origin = 'participant';
                }
                if (out.members.length === 0) {
                    out.origin = '???';
                } else if (out.members.indexOf(out.source) >= 0) {
                    out.origin = 'outsider';
                }

                // Recovery.
                out.recover = greeter.isRecoverBitOnMessageType(out.messageTypeNumber);
            }
        }
        return out;
    };


    /**
     * Determines of a messages message type.
     *
     * @param message {string}
     *     A wire protocol message representation.
     * @returns {string}
     *     The two byte message type string.
     */
    ns.getMessageType = function(message) {
        if (!message) {
            return undefined;
        }

        while (message.length > 0) {
            var tlv = ns.decodeTLV(message);
            if (tlv.type === ns.TLV_TYPE.MESSAGE_TYPE) {
                return tlv.value;
            }
            message = tlv.rest;
        }
        return undefined;
    };


    /**
     * Detects the category of a given message.
     *
     * @param message {string}
     *     A wire protocol message representation.
     * @returns {mpenc.codec.MESSAGE_CATEGORY}
     *     Object indicating message `category` and extracted message `content`.
     */
    ns.categoriseMessage = function(message) {
        if (!message) {
            return null;
        }

        // Check for plain text or "other".
        if (message.substring(0, _PROTOCOL_PREFIX.length) !== _PROTOCOL_PREFIX) {
            return { category: ns.MESSAGE_CATEGORY.PLAIN,
                     content: message };
        }
        message = message.substring(_PROTOCOL_PREFIX.length);

        // Check for error.
        var _ERROR_PREFIX = ' Error:';
        if (message.substring(0, _ERROR_PREFIX.length) === _ERROR_PREFIX) {
            return { category: ns.MESSAGE_CATEGORY.MPENC_ERROR,
                     content: message.substring(_PROTOCOL_PREFIX.length + 1) };
        }

        // Check for mpENC message.
        if ((message[0] === ':') && (message[message.length - 1] === '.')) {
            message = atob(message.substring(1, message.length - 1));
            if (ns.getMessageType(message) === greeter.MESSAGE_TYPE.PARTICIPANT_DATA) {
                return { category: ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                         content: message };
            } else {
                return { category: ns.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                         content: message };
            }
        }

        // Check for query.
        var ver = /v(\d+)\?/.exec(message);
        if (ver && (ver[1] === '' + version.PROTOCOL_VERSION.charCodeAt(0))) {
            return { category: ns.MESSAGE_CATEGORY.MPENC_QUERY,
                     content: String.fromCharCode(ver[1]) };
        }

        _assert(false, 'Unknown mpENC message.');
    };


    /**
     * Encodes a given value to a binary TLV string of a given type.
     *
     * @param tlvType {integer}
     *     Type of string to use (16-bit unsigned integer).
     * @param value {string}
     *     A binary string of the pay load to carry. If omitted, no value
     *     (null) is used.
     * @returns {string}
     *     A binary TLV string.
     */
    ns.encodeTLV = function(tlvType, value) {
        if ((value === null) || (value === undefined)) {
            value = '';
        }
        value += '';
        var out = ns._short2bin(tlvType);
        out += ns._short2bin(value.length);
        return out + value;
    };


    /**
     * Encodes an array of values to a binary TLV string of a given type.
     *
     * @param tlvType {integer}
     *     Type of string to use (16-bit unsigned integer).
     * @param valueArray {Array}
     *     The array of values.
     * @returns {string}
     *     A binary TLV string.
     */
    ns._encodeTlvArray = function(tlvType, valueArray) {
        _assert((valueArray instanceof Array) || (valueArray === null),
                'Value passed neither an array or null.');

        // Trivial case, quick exit.
        if ((valueArray === null) || (valueArray.length === 0)) {
            return '';
        }

        var out = '';
        for (var i = 0; i < valueArray.length; i++) {
            out += ns.encodeTLV(tlvType, valueArray[i]);
        }
        return out;
    };


    var ENCODED_VERSION;
    var ENCODED_TYPE_MESSAGE_DATA;


    /**
     * Encodes a given data message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param message {string}
     *     Message as string.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param sessionKeyStore {mpenc.greet.keystore.KeyStore}
     *     Store for (sub-) session related keys and information. Mandatory for
     *     data messages, ignored for protocol messages.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {string}
     *     A wire ready message representation.
     */
    ns.encodeDataMessage = function(message, privKey, pubKey,
                                    sessionKeyStore, paddingSize) {
        if (message === null || message === undefined) {
            return null;
        }
        paddingSize = paddingSize | 0;
        var out = '';
        // We want message attributes in this order:
        // sid/key hint, message signature, protocol version, message type,
        // iv, message data
        var sessionID = sessionKeyStore.sessionIDs[0];
        var groupKey = sessionKeyStore.sessions[sessionID].groupKeys[0];

        // Three portions: unsigned content (hint), signature, rest.
        // Compute info for the SIDKEY_HINT and signature.
        var sidkeyHash = utils.sha256(sessionID + groupKey);

        // Rest (protocol version, message type, iv, message data).
        var content = ENCODED_VERSION + ENCODED_TYPE_MESSAGE_DATA;
        var encrypted = ns.encryptDataMessage(message, groupKey, paddingSize);
        content += ns.encodeTLV(ns.TLV_TYPE.MESSAGE_IV, encrypted.iv);
        content += ns.encodeTLV(ns.TLV_TYPE.DATA_MESSAGE, encrypted.data);

        // Compute the content signature.
        var signature = ns.signMessage(ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE,
                                       content, privKey, pubKey, sidkeyHash);

        // Assemble everything.
        out = ns.encodeTLV(ns.TLV_TYPE.SIDKEY_HINT, sidkeyHash[0]);
        out += ns.encodeTLV(ns.TLV_TYPE.MESSAGE_SIGNATURE, signature);
        out += content;
        return _PROTOCOL_PREFIX + ':' + btoa(out) + '.';
    };

    /**
     * Encodes a given greet message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param message {mpenc.greet.greeter.ProtocolMessage}
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
     *     A wire ready message representation.
     */
    ns.encodeGreetMessage = function(message, privKey, pubKey, paddingSize) {
        if (message === null || message === undefined) {
            return null;
        }
        paddingSize = paddingSize | 0;

        var out = ENCODED_VERSION;
        // Process message attributes in this order:
        // messageType, source, dest, members, intKeys, nonces, pubKeys,
        // sessionSignature, signingKey
        out += ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, message.messageType);
        out += ns.encodeTLV(ns.TLV_TYPE.SOURCE, message.source);
        out += ns.encodeTLV(ns.TLV_TYPE.DEST, message.dest);
        if (message.members) {
            out += ns._encodeTlvArray(ns.TLV_TYPE.MEMBER, message.members);
        }
        if (message.intKeys) {
            out += ns._encodeTlvArray(ns.TLV_TYPE.INT_KEY, message.intKeys);
        }
        if (message.nonces) {
            out += ns._encodeTlvArray(ns.TLV_TYPE.NONCE, message.nonces);
        }
        if (message.pubKeys) {
            out += ns._encodeTlvArray(ns.TLV_TYPE.PUB_KEY, message.pubKeys);
        }
        if (message.sessionSignature) {
            out += ns.encodeTLV(ns.TLV_TYPE.SESSION_SIGNATURE, message.sessionSignature);
        }
        if (message.signingKey) {
            out += ns.encodeTLV(ns.TLV_TYPE.SIGNING_KEY, message.signingKey);
        }
        // Sign `out` and prepend signature.
        var signature = ns.signMessage(ns.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                                       out, privKey, pubKey);
        out = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_SIGNATURE, signature) + out;

        return _PROTOCOL_PREFIX + ':' + btoa(out) + '.';
    };

    /**
     * Encodes a given error message ready to be put onto the wire, using
     * clear text for most things, and base64 encoding for the signature.
     *
     * @param from {string}
     *     Participant ID of the sender.
     * @param severity {string}
     *     Severity of the error message.
     * @param message {string}
     *     Error text to include in the message.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @returns {string}
     *     A wire ready message representation.
     */
    ns.encodeErrorMessage = function(from, severity, message, privKey, pubKey) {
        if (message === null || message === undefined) {
            return null;
        }
        var out = 'from "' + from +'":' + severity + ':' + message;
        var signature = '';
        if (privKey) {
            signature = ns.signMessage(ns.MESSAGE_CATEGORY.MPENC_ERROR,
                                       out, privKey, pubKey);
        }
        return _PROTOCOL_PREFIX + ' Error:' + btoa(signature) + ':' + out;
    };


    /**
     * Converts an unsigned short integer to a binary string.
     *
     * @param value {integer}
     *     A 16-bit unsigned integer.
     * @returns {string}
     *     A two character binary string.
     */
    ns._short2bin = function(value) {
        return String.fromCharCode(value >> 8) + String.fromCharCode(value & 0xff);
    };


    /**
     * Converts a binary string to an unsigned short integer.
     *
     * @param value {string}
     *     A two character binary string.
     * @returns {integer}
     *     A 16-bit unsigned integer.
     */
    ns._bin2short= function(value) {
        return (value.charCodeAt(0) << 8) | value.charCodeAt(1);
    };


    /**
     * Encrypts a given data message.
     *
     * The data message is encrypted using AES-128-CTR, and a new random
     * IV/nonce (12 byte) is generated and returned.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {Object}
     *     An object containing the message (in `data`, binary string) and
     *     the IV used (in `iv`, binary string).
     */
    ns.encryptDataMessage = function(data, key, paddingSize) {
        if (data === null || data === undefined) {
            return null;
        }
        paddingSize = paddingSize | 0;
        var keyBytes = new Uint8Array(jodid25519.utils.string2bytes(key));
        var nonceBytes = utils._newKey08(96);
        // Protect multi-byte characters.
        var dataBytes = unescape(encodeURIComponent(data));
        // Prepend length in bytes to message.
        _assert(dataBytes.length < 0xffff,
                'Message size too large for encryption scheme.');
        dataBytes = ns._short2bin(dataBytes.length) + dataBytes;
        if (paddingSize) {
            // Compute exponential padding size.
            var exponentialPaddingSize = paddingSize
                                       * (1 << Math.ceil(Math.log(Math.ceil((dataBytes.length) / paddingSize))
                                                         / Math.log(2))) + 1;
            var numPaddingBytes = exponentialPaddingSize - dataBytes.length;
            dataBytes += (new Array(numPaddingBytes)).join('\u0000');
        }
        var ivBytes = new Uint8Array(nonceBytes.concat(utils.arrayMaker(4, 0)));
        var cipherBytes = asmCrypto.AES_CTR.encrypt(dataBytes, keyBytes, ivBytes);
        return { data: jodid25519.utils.bytes2string(cipherBytes),
                 iv: jodid25519.utils.bytes2string(nonceBytes) };
    };


    /**
     * Decrypts a given data message.
     *
     * The data message is decrypted using AES-128-CTR.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @param iv {string}
     *     Binary string representation of 96-bit nonce/IV.
     * @returns {string}
     *     The clear text message as a binary string.
     */
    ns.decryptDataMessage = function(data, key, iv) {
        if (data === null || data === undefined) {
            return null;
        }
        var keyBytes = new Uint8Array(jodid25519.utils.string2bytes(key));
        var nonceBytes = jodid25519.utils.string2bytes(iv);
        var ivBytes = new Uint8Array(nonceBytes.concat(utils.arrayMaker(4, 0)));
        var clearBytes = asmCrypto.AES_CTR.decrypt(data, keyBytes, ivBytes);
        // Strip off message size and zero padding.
        var clearString = jodid25519.utils.bytes2string(clearBytes);
        var messageSize = ns._bin2short(clearString.slice(0, 2));
        clearString = clearString.slice(2, messageSize + 2);
        // Undo protection for multi-byte characters.
        return decodeURIComponent(escape(clearString));
    };


    /**
     * Signs a given data message with the ephemeral private key.
     *
     * This implementation is using the Edwards25519 for an ECDSA signature
     * mechanism to complement the Curve25519-based group key agreement.
     *
     * @param category {integer}
     *     Message category indication, one of
     *     {@see mpenc/codec.MESSAGE_CATEGORY}.
     * @param data {string}
     *     Binary string data message.
     * @param privKey {string}
     *     Binary string representation of the ephemeral private key.
     * @param pubKey {string}
     *     Binary string representation of the ephemeral public key.
     * @property sidkeyHash {string}
     *     On {MPENC_DATA_MESSAGE} relevant only. A hash value hinting at the
     *     right combination of session ID and group key used for a data message.
     * @returns {string}
     *     Binary string representation of the signature.
     */
    ns.signMessage= function(category, data, privKey, pubKey, sidkeyHash) {
        if (data === null || data === undefined) {
            return null;
        }
        var prefix = _MAGIC_NUMBERS[category];
        if (category === ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE) {
            prefix += sidkeyHash;
        }
        return jodid25519.eddsa.sign(prefix + data, privKey, pubKey);
    };


    /**
     * Checks the signature of a given data message with the ephemeral public key.
     *
     * This implementation is using the Edwards25519 for an ECDSA signature
     * mechanism to complement the Curve25519-based group key agreement.
     *
     * @param category {integer}
     *     Message category indication, one of
     *     {@see mpenc/codec.MESSAGE_CATEGORY}.
     * @param data {string}
     *     Binary string data message.
     * @param signature {string}
     *     Binary string representation of the signature.
     * @param pubKey {string}
     *     Binary string representation of the ephemeral public key.
     * @property sidkeyHash {string}
     *     On {MPENC_DATA_MESSAGE} relevant only. A hash value hinting at the
     *     right combination of session ID and group key used for a data message.
     * @returns {bool}
     *     True if the signature verifies, false otherwise.
     */
    ns.verifyMessageSignature = function(category, data, signature, pubKey, sidkeyHash) {
        if (data === null || data === undefined) {
            return null;
        }
        var prefix = _MAGIC_NUMBERS[category];
        if (category === ns.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE) {
            prefix += sidkeyHash;
        }
        return jodid25519.eddsa.verify(signature, prefix + data, pubKey);
    };


    /**
     * Returns an mpENC protocol query message ready to be put onto the wire,
     * including.the given message.
     *
     * @param text {string}
     *     Text message to accompany the mpENC protocol query message.
     * @returns {string}
     *     A wire ready message representation.
     */
    ns.getQueryMessage = function(text) {
        return _PROTOCOL_PREFIX + 'v' + version.PROTOCOL_VERSION.charCodeAt(0) + '?' + text;
    };


    ENCODED_VERSION = ns.encodeTLV(ns.TLV_TYPE.PROTOCOL_VERSION, version.PROTOCOL_VERSION);
    ENCODED_TYPE_MESSAGE_DATA = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, greeter.MESSAGE_TYPE.PARTICIPANT_DATA);


    return ns;
});
