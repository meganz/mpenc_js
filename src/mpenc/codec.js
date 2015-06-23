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
    "asmcrypto",
    "jodid25519",
    "megalogger",
], function(assert, utils, version, asmCrypto, jodid25519, MegaLogger) {
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
     * "Enumeration" of protocol message types.
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
    ns.MESSAGE_TYPE = {
        PLAIN:               0x00,
        MPENC_QUERY:         0x01,
        MPENC_GREET_MESSAGE: 0x02,
        MPENC_DATA_MESSAGE:  0x03,
        MPENC_ERROR:         0x04,
    };


    // Add reverse mapping to string representation.
    ns.MESSAGE_TYPE_MAPPING = {};
    for (var propName in ns.MESSAGE_TYPE) {
        ns.MESSAGE_TYPE_MAPPING[ns.MESSAGE_TYPE[propName]] = propName;
    }


    // "Magic numbers" used for prepending the data for the purpose of signing.
    var _MAGIC_NUMBERS = {};
    _MAGIC_NUMBERS[ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE] = 'greetmsgsig';
    _MAGIC_NUMBERS[ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE] = 'datamsgsig';
    _MAGIC_NUMBERS[ns.MESSAGE_TYPE.MPENC_ERROR] = 'errormsgsig';


    /**
     * "Enumeration" for TLV record types.
     *
     * @property MESSAGE_SIGNATURE {string}
     *     Signature of the entire message sent (must be the first TLV sent,
     *     and sign *all* remaining binary content).
     * @property PROTOCOL_VERSION {integer}
     *     Indicates the protocol version to be used as a 8-bit unsigned integer.
     * @property MESSAGE_TYPE {integer}
     *     Indicates the message type as a 8-bit unsigned integer.
     * @property MESSAGE_PAYLOAD {string}
     *     Public data payload of the message. Also used for error messages.
     *
     * @property MESSAGE_IV {string}
     *     Random initialisation vector for encrypted message payload.
     * @property SIDKEY_HINT {integer}
     *     1-byte hint at the right combination of session ID and group key used
     *     for a data message. May appear as the first record, before a signature.
     * @property MESSAGE_PARENT {string}
     *     Direct parent id of the message, as seen by its author.
     * @property MESSAGE_BODY {string}
     *     Secret content of the message.
     *
     * @property GREET_TYPE {integer}
     *     mpENC key agreement message type. See {@link mpenc.greet.greeter.GREET_TYPE}.
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
        MESSAGE_SIGNATURE: 0x0003, // 3
        PROTOCOL_VERSION:  0x0001, // 1
        MESSAGE_TYPE:      0x0002, // 2
        MESSAGE_PAYLOAD:   0x0010, // 16
        // Data messages
        MESSAGE_IV:        0x0011, // 17
        SIDKEY_HINT:       0x0012, // 18
        MESSAGE_PARENT:    0x0013, // 19
        MESSAGE_BODY:      0x0014, // 20
        // Greet messages
        GREET_TYPE:        0x01ff, // 511
        SOURCE:            0x0100, // 256
        DEST:              0x0101, // 257
        MEMBER:            0x0102, // 258
        INT_KEY:           0x0103, // 259
        NONCE:             0x0104, // 260
        PUB_KEY:           0x0105, // 261
        SESSION_SIGNATURE: 0x0106, // 262
        SIGNING_KEY:       0x0107, // 263
        // Greet proposal messages
        PREV_PF:           0x0301,
        CHAIN_HASH:        0x0302,
        LATEST_PM:         0x0303,
        // Error messages
        SEVERITY:          0x0201, // 513
    };


    /**
     * "Enumeration" defining the different mpENC error message severities.
     *
     * @property INFO {integer}
     *     An informational message with no or very low severity.
     * @property WARNING {integer}
     *     An warning message.
     * @property ERROR {integer}
     *     An error message with high severity.
     * @property TERMINAL {integer}
     *     A terminal error message that demands the immediate termination of
     *     all protocol execution. It should be followed by each participant's
     *     immediate invocation of a quit protocol flow.
     */
    ns.ERROR = {
        INFO:          0x00,
        WARNING:       0x01,
        TERMINAL:      0x02
    };

    // Add reverse mapping to string representation.
    ns._ERROR_MAPPING = {};
    for (var propName in ns.ERROR) {
        ns._ERROR_MAPPING[ns.ERROR[propName]] = propName;
    }


    ns.decodeError = function(message) {
        throw new Error("decode failed: " + message);
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


    var _getMessageType = function(message) {
        if (!message) {
            return undefined;
        }

        while (message.length > 0) {
            var tlv = ns.decodeTLV(message);
            if (tlv.type === ns.TLV_TYPE.MESSAGE_TYPE) {
                return tlv.value.charCodeAt(0);
            }
            message = tlv.rest;
        }
        return undefined;
    };


    /**
     * Encodes an mpENC TLV string suitable for sending onto the wire.
     */
    ns.encodeWirePacket = function(contents) {
        return _PROTOCOL_PREFIX + ':' + btoa(contents) + '.';
    };


    /**
     * Decodes a given binary TLV string to a type and value.
     *
     * @param tlv {string}
     *     A binary TLV string.
     * @returns {Object}
     *     An object containing the type of string (in `type`, 16-bit unsigned
     *     integer) and the value (in `value`, binary string of the pay load).
     *     left over bytes from the input are returned in `rest`.
     */
    ns.decodeTLV = function(tlv) {
        _assert(typeof tlv === "string", "tried to decode non-string");
        var type = ns._bin2short(tlv.substring(0, 2));
        var length = ns._bin2short(tlv.substring(2, 4));
        var value = tlv.substring(4, 4 + length);
        _assert(length === value.length,
                'TLV payload length does not match indicated length: type ' + type +
                "; expected " + length + "; actual " + value.length);
        if (length === 0) {
            value = '';
        }
        return {
            type: type,
            value: value,
            rest: tlv.substring(length + 4)
        };
    };


    /**
     * Decodes a given TLV value of a particular type, and do something with it.
     *
     * @param message {string}
     *     A binary TLV string.
     * @param type {string}
     *     Expected type of the TLV; throws an error if this doesn't match.
     * @param action {function}
     *     1-arg function to execute on the decoded value.
     * @returns {string}
     *     The rest of the string to decode later.
     */
    ns.popTLV = function(message, type, action) {
        var tlv = ns.decodeTLV(message);
        tlv.type === type || ns.decodeError("expected TLV type " + type + " but got " + tlv.type);
        action(tlv.value);
        return tlv.rest;
    };


    /**
     * Decodes PROTOCOL_VERSION and MESSAGE_TYPE, present on all messages.
     *
     * @param message {string}
     *     A binary TLV string.
     * @param expectedType {string}
     *     Expected MESSAGE_TYPE, otherwise an error will be thrown.
     * @returns {string}
     *     The rest of the string to decode later.
     */
    ns.popStandardFields = function(message, expectedType, debugOutput) {
        debugOutput = debugOutput || [];
        var rest = message;
        rest = ns.popTLV(rest, ns.TLV_TYPE.PROTOCOL_VERSION, function(value) {
            value.length === 1 || ns.decodeError("unexpected length for PROTOCOL_VERSION");
            value = value.charCodeAt(0);

            value === version.PROTOCOL_VERSION || ns.decodeError(
                "expected PROTOCOL_VERSION " + version.PROTOCOL_VERSION + " but got " + value);
            debugOutput.push('protocol: ' + value);
        });
        rest = ns.popTLV(rest, ns.TLV_TYPE.MESSAGE_TYPE, function(value) {
            value.length === 1 || ns.decodeError("unexpected length for MESSAGE_TYPE");
            value = value.charCodeAt(0);

            value === expectedType || ns.decodeError(
                "expected message type: " + expectedType + " but got: " + value);
            debugOutput.push('messageType: 0x'
                             + value.toString(16)
                             + ' (' + ns.MESSAGE_TYPE_MAPPING[value] + ')');
        });
        return rest;
    };


    /**
     * Decodes a given TLV value. If it matchs the expected type, run the action.
     * Otherwise do nothing and return the original string.
     */
    ns.popTLVMaybe = function(message, type, action) {
        var tlv = ns.decodeTLV(message);
        if (tlv.type !== type) {
            return message;
        }
        action(tlv.value);
        return tlv.rest;
    };


    /**
     * Keep decoding TLV values of a particular type, executing the action on
     * each decoded value. Stop when the next value is not of the expected type.
     *
     * @param message {string}
     *     A binary TLV string.
     * @param type {string}
     *     Expected type of the TLV.
     * @param action {function}
     *     1-arg function to execute on each decoded value.
     * @returns {string}
     *     The rest of the string to decode later.
     */
    ns.popTLVAll = function(message, type, action) {
        var oldrest;
        var rest = message;
        do {
            oldrest = rest;
            rest = ns.popTLVMaybe(rest, type, action);
        } while (rest !== oldrest);
        return rest;
    };


    /**
     * Keep decoding TLV values *until* we reach a particular type. Stop when
     * the next value is of the expected type.
     *
     * @param message {string}
     *     A binary TLV string.
     * @param type {string}
     *     Expected type of the TLV to search for.
     * @returns {string}
     *     A string that is either empty or whose next record is of the given type.
     */
    ns.popTLVUntil = function(message, type) {
        var oldrest;
        var rest = message;
        do {
            oldrest = rest;
            var tlv = ns.decodeTLV(rest);
            if (tlv.type === type) {
                break;
            }
            rest = tlv.rest;
        } while (rest !== oldrest);
        return rest;
    };


    /**
     * Detects the type of a given message.
     *
     * @param message {string}
     *     A wire protocol message representation.
     * @returns {mpenc.codec.MESSAGE_TYPE}
     *     Object indicating message `type` and decoded TLV string `content`.
     */
    ns.decodeWirePacket = function(message) {
        if (!message) {
            return null;
        }

        // Check for plain text or "other".
        if (message.substring(0, _PROTOCOL_PREFIX.length) !== _PROTOCOL_PREFIX) {
            return { type: ns.MESSAGE_TYPE.PLAIN, content: message };
        }
        message = message.substring(_PROTOCOL_PREFIX.length);

        // Check for mpENC message.
        if ((message[0] === ':') && (message[message.length - 1] === '.')) {
            message = atob(message.substring(1, message.length - 1));
            var type = _getMessageType(message);
            if (type in ns.MESSAGE_TYPE_MAPPING) {
                return { type: type, content: message };
            }
        }

        _assert(false, 'Unknown mpENC message.');
    };


    /**
     * Encodes a given error message.
     *
     * @param error {object}
     *     Descriptor object for the error; must contain these properties:
     *     from: Participant ID of the sender;
     *     severity: Severity of the error message;
     *     message: Error text to include in the message.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @returns {string}
     *     A TLV string.
     */
    ns.encodeErrorMessage = function(error, privKey, pubKey) {
        if (error === null || error === undefined) {
            return null;
        }

        var content = ns.ENCODED_VERSION + ns.ENCODED_TYPE_ERROR;
        content += ns.encodeTLV(ns.TLV_TYPE.SOURCE, error.from);
        if (!ns._ERROR_MAPPING[error.severity]) {
            throw new Error('Illegal error severity: ' + error.severity + '.');
        }
        content += ns.encodeTLV(ns.TLV_TYPE.SEVERITY, String.fromCharCode(error.severity));
        content += ns.encodeTLV(ns.TLV_TYPE.MESSAGE_PAYLOAD, error.message);

        if (privKey) {
            var signature = ns.signMessage(ns.MESSAGE_TYPE.MPENC_ERROR,
                                           content, privKey, pubKey);
            return ns.encodeTLV(ns.TLV_TYPE.MESSAGE_SIGNATURE, signature) + content;
        } else {
            return content;
        }
    };


    /**
     * Decodes a given error message.
     *
     * @param content {string}
     *     A TLV string.
     * @returns {object}
     *     The error descriptor object, documented in {@link #encodeMessage()}.
     *     Has the additional field `signatureOk` {?bool} (`true` if signature
     *     verifies, `false` if failed, `null` if signature does not exist or
     *     could not be verified).
     */
    ns.decodeErrorMessage = function(content, getPubKey) {
        var debugOutput = [];
        var out = {};
        out.signatureOk = null;
        var rest = content;

        rest = ns.popTLVMaybe(rest, ns.TLV_TYPE.MESSAGE_SIGNATURE, function(value) {
            out.signature = value;
        });
        if (out.signature) {
            out.signatureOk = ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_ERROR,
                                                        rest, out.signature, getPubKey(out.from));
        }

        rest = ns.popStandardFields(rest, ns.MESSAGE_TYPE.MPENC_ERROR);
        rest = ns.popTLV(rest, ns.TLV_TYPE.SOURCE, function(value) {
            out.from = value;
        });
        rest = ns.popTLV(rest, ns.TLV_TYPE.SEVERITY, function(value) {
            out.severity = value.charCodeAt(0);
        });
        rest = ns.popTLV(rest, ns.TLV_TYPE.MESSAGE_PAYLOAD, function(value) {
            out.message = value;
        });

        return out;
    };


    ns.errorToUiString = function(error) {
        var uiMessageString = ns._ERROR_MAPPING[error.severity];
        if (error.severity === ns.ERROR.TERMINAL) {
            uiMessageString += ' ERROR';
        }
        uiMessageString += ': ' + error.message;
        return uiMessageString;
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
    ns._bin2short = function(value) {
        return (value.charCodeAt(0) << 8) | value.charCodeAt(1);
    };


    /**
     * Signs a given data message with the ephemeral private key.
     *
     * This implementation is using the Edwards25519 for an ECDSA signature
     * mechanism to complement the Curve25519-based group key agreement.
     *
     * @param type {integer}
     *     Message type, one of {@see mpenc/codec.MESSAGE_TYPE}.
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
    ns.signMessage = function(type, data, privKey, pubKey, sidkeyHash) {
        if (data === null || data === undefined) {
            return null;
        }
        var prefix = _MAGIC_NUMBERS[type];
        if (type === ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE) {
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
     * @param type {integer}
     *     Message type, one of {@see mpenc/codec.MESSAGE_TYPE}.
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
    ns.verifyMessageSignature = function(type, data, signature, pubKey, sidkeyHash) {
        if (data === null || data === undefined) {
            return null;
        }
        var prefix = _MAGIC_NUMBERS[type];
        if (type === ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE) {
            prefix += sidkeyHash;
        }
        return jodid25519.eddsa.verify(signature, prefix + data, pubKey);
    };


    ns.ENCODED_VERSION = ns.encodeTLV(ns.TLV_TYPE.PROTOCOL_VERSION, String.fromCharCode(version.PROTOCOL_VERSION));
    ns.ENCODED_TYPE_DATA = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, String.fromCharCode(ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE));
    ns.ENCODED_TYPE_GREET = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, String.fromCharCode(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE));
    ns.ENCODED_TYPE_QUERY = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, String.fromCharCode(ns.MESSAGE_TYPE.MPENC_QUERY));
    ns.ENCODED_TYPE_ERROR = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_TYPE, String.fromCharCode(ns.MESSAGE_TYPE.MPENC_ERROR));
    ns.PROTOCOL_VERSION = version.PROTOCOL_VERSION;

    /**
     * String representing an mpENC query message.
     */
    ns.MPENC_QUERY_MESSAGE = ns.ENCODED_VERSION + ns.ENCODED_TYPE_QUERY;

    return ns;
});
