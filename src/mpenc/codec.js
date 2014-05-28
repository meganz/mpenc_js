/**
 * @fileOverview
 * Implementation of a protocol encoder/decoder.
 */

define([
    "mpenc/helper/assert",
    "mpenc/messages",
    "mpenc/helper/utils",
    "mpenc/version",
    "asmcrypto",
    "jodid25519",
], function(assert, messages, utils, version, asmCrypto, jodid25519) {
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

    var _ZERO_BYTE = '\u0000';
    var _ONE_BYTE = '\u0001';
    var _PROTOCOL_INDICATOR = 'mpENC';
    var _PROTOCOL_PREFIX = '?' + _PROTOCOL_INDICATOR;

    /*
     * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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
     * "Enumeration" protocol message category types.
     *
     * @property PLAIN {integer}
     *     Plain text message (not using mpENC).
     * @property MPENC_QUERY {integer}
     *     Query to initiate an mpENC session.
     * @property MPENC_MESSAGE {integer}
     *     mpENC message.
     * @property MPENC_ERROR {integer}
     *     Message for error in mpENC protocol.
     */
    ns.MESSAGE_CATEGORY = {
        PLAIN:             0x00,
        MPENC_QUERY:       0x01,
        MPENC_MESSAGE:     0x02,
        MPENC_ERROR:       0x03,
    };


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
     * @property SOURCE {integer}
     *     Message originator ("from", must be only one).
     * @property DEST {integer}
     *     Message destination ("to", should be only one, broadcast if not
     *     present or empty).
     * @property AUX_AGREEMENT {integer}
     *     Type of key agreement. Binary 0 for "initial" or 1 for "auxiliary".
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
        SOURCE:            0x0100, // 256
        DEST:              0x0101, // 257
        AUX_AGREEMENT:     0x0102, // 258
        MEMBER:            0x0103, // 259
        INT_KEY:           0x0104, // 260
        NONCE:             0x0105, // 261
        PUB_KEY:           0x0106, // 262
        SESSION_SIGNATURE: 0x0107, // 263
        SIGNING_KEY:       0x0108, // 264
    };


    /**
     * "Enumeration" message types.
     *
     * FIXME: This needs some serious work.
     *
     * @property DATA {integer}
     *     Used to transmit a private message.
     */
    ns.MESSAGE_TYPE = {
        DATA:              0x03,
        KEY_AGREEMENT:     0x0a,
        REVEAL_SIGNATURE:  0x11,
        SIGNATURE:         0x12,
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
        if (value.length === 0) {
            value = null;
        }
        return {
            type: type,
            value: value,
            rest: tlv.substring(length + 4)
        };
    };


    /**
     * Decodes a given TLV encoded protocol message content into an object.
     *
     * @param message {string}
     *     A binary message representation.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @returns {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     */
    ns.decodeMessageContent = function(message, groupKey, pubKey) {
        if (!message) {
            return null;
        }

        var out = new messages.ProtocolMessage();

        while (message.length > 0) {
            var tlv = ns.decodeTLV(message);
            switch (tlv.type) {
                case ns.TLV_TYPE.PADDING:
                    // Completely ignore this.
                    break;
                case ns.TLV_TYPE.PROTOCOL_VERSION:
                    out.protocol = tlv.value;
                    break;
                case ns.TLV_TYPE.SOURCE:
                    out.source = tlv.value;
                    break;
                case ns.TLV_TYPE.DEST:
                    out.dest = tlv.value || '';
                    if (out.dest === '') {
                        out.flow = 'downflow';
                    } else {
                        out.flow = 'upflow';
                    }
                    break;
                case ns.TLV_TYPE.AUX_AGREEMENT:
                    if (tlv.value === _ZERO_BYTE) {
                        out.agreement = 'initial';
                    } else if (tlv.value === _ONE_BYTE) {
                        out.agreement = 'auxilliary';
                    } else {
                        _assert(false,
                                'Unexpected value for agreement TLV: '
                                + tlv.value.charCodeAt(0) + '.');
                    }
                    break;
                case ns.TLV_TYPE.MEMBER:
                    out.members.push(tlv.value);
                    break;
                case ns.TLV_TYPE.INT_KEY:
                    out.intKeys.push(tlv.value);
                    break;
                case ns.TLV_TYPE.NONCE:
                    out.nonces.push(tlv.value);
                    break;
                case ns.TLV_TYPE.PUB_KEY:
                    out.pubKeys.push(tlv.value);
                    break;
                case ns.TLV_TYPE.SESSION_SIGNATURE:
                    out.sessionSignature = tlv.value;
                    break;
                case ns.TLV_TYPE.SIGNING_KEY:
                    out.signingKey = tlv.value;
                    break;
                case ns.TLV_TYPE.MESSAGE_SIGNATURE:
                    out.signature = tlv.value;
                    out.rawMessage = tlv.rest;
                    break;
                case ns.TLV_TYPE.MESSAGE_IV:
                    out.iv = tlv.value;
                    break;
                case ns.TLV_TYPE.DATA_MESSAGE:
                    out.data = tlv.value;
                    break;
                default:
                    _assert(false, 'Received unknown TLV type: ' + tlv.type);
                    break;
            }

            message = tlv.rest;
        }

        // Some specifics depending on the type of mpENC message.
        if (out.data) {
            // Some further crypto processing on data messages.
            out.data = ns.decryptDataMessage(out.data, groupKey, out.iv);
        } else {
            // Some sanity checks for keying messages.
            _assert(out.intKeys.length <= out.members.length,
                    'Number of intermediate keys cannot exceed number of members.');
            _assert(out.nonces.length <= out.members.length,
                    'Number of nonces cannot exceed number of members.');
            _assert(out.pubKeys.length <= out.members.length,
                    'Number of public keys cannot exceed number of members.');
        }

        // Check signature, if present.
        if (out.signature) {
            if (!pubKey) {
                var index = out.members.indexOf(out.source);
                pubKey = out.pubKeys[index];
            }
            try {
                out.signatureOk = ns.verifyDataMessage(out.rawMessage,
                                                       out.signature,
                                                       pubKey);
                _assert(out.signatureOk,
                        'Signature of message does not verify!');
            } catch (e) {
                out.signatureOk = false;
                _assert(out.signatureOk,
                        'Signature of message does not verify: ' + e + '!');
            }
        }

        _assert(out.protocol === version.PROTOCOL_VERSION,
                'Received wrong protocol version: ' + out.protocol.charCodeAt(0) + '.');

        return out;
    };


    /**
     * Detects the category of a given message.
     *
     * @param message {string}
     *     A wire protocol message representation.
     * @returns {mpenc.codec.MESSAGE_CATEGORY}
     *     Message category indicator.
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

        // Check for message.
        if ((message[0] === ':') && (message[message.length - 1] === '.')) {
            return { category: ns.MESSAGE_CATEGORY.MPENC_MESSAGE,
                     content: atob(message.substring(1, message.length - 1)) };
        }

        // Check for query.
        var ver = /v(\d+)\?/.exec(message);
        if (ver && (ver[1] === '' + version.PROTOCOL_VERSION.charCodeAt(0))) {
            return { category: ns.MESSAGE_CATEGORY.MPENC_QUERY,
                     content: String.fromCharCode(ver[1]) };
        }

        _assert(false, 'Unknown mpEnc message.');
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


    /**
     * Encodes a given protocol message content into a binary string message
     * consisting of a sequence of TLV binary strings.
     *
     * @param message {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @returns {string}
     *     A binary message representation.
     */
    ns.encodeMessageContent = function(message, groupKey, privKey, pubKey) {
        var out = ns.encodeTLV(ns.TLV_TYPE.PROTOCOL_VERSION, version.PROTOCOL_VERSION);
        if (typeof(message) === 'string' || message instanceof String) {
            // We're dealing with a message containing user content.
            var encrypted = ns.encryptDataMessage(message, groupKey);

            // We want message attributes in this order:
            // signature, protocol version, iv, message data
            out += ns.encodeTLV(ns.TLV_TYPE.MESSAGE_IV, encrypted.iv);
            out += ns.encodeTLV(ns.TLV_TYPE.DATA_MESSAGE, encrypted.data);
            // Sign `out` and prepend signature.
            var signature = ns.signDataMessage(out, privKey, pubKey);
            out = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_SIGNATURE, signature) + out;
        } else {
            // Process message attributes in this order:
            // source, dest, agreement, members, intKeys, nonces, pubKeys,
            // sessionSignature, signingKey

            out += ns.encodeTLV(ns.TLV_TYPE.SOURCE, message.source);
            out += ns.encodeTLV(ns.TLV_TYPE.DEST, message.dest);
            if (message.agreement === 'initial') {
                out += ns.encodeTLV(ns.TLV_TYPE.AUX_AGREEMENT, _ZERO_BYTE);
            } else {
                out += ns.encodeTLV(ns.TLV_TYPE.AUX_AGREEMENT, _ONE_BYTE);
            }
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
            var signature = ns.signDataMessage(out, privKey, pubKey);
            out = ns.encodeTLV(ns.TLV_TYPE.MESSAGE_SIGNATURE, signature) + out;
        }

        return out;
    };


    /**
     * Encodes a given protocol message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param message {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @returns {string}
     *     A wire ready message representation.
     */
    ns.encodeMessage = function(message, groupKey, privKey, pubKey) {
        if (message === null || message === undefined) {
            return null;
        }
        var content = ns.encodeMessageContent(message, groupKey, privKey, pubKey);
        return _PROTOCOL_PREFIX + ':' + btoa(content) + '.';
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
        return (value.charCodeAt(0) << 8) + value.charCodeAt(1);
    };


    /**
     * Encrypts a given data message.
     *
     * The data message is encrypted using AES-128-CBC, and a new random IV is
     * generated and returned.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @returns {Object}
     *     An object containing the message (in `data`, binary string) and
     *     the IV used (in `iv`, binary string).
     */
    ns.encryptDataMessage = function(data, key) {
        if (data === null || data === undefined) {
            return null;
        }
        var keyBytes = new Uint8Array(jodid25519.eddsa.string2bytes(key));
        var ivBytes = new Uint8Array(utils._newKey08(128));
        // Protect multi-byte characters.
        var dataBytes = unescape(encodeURIComponent(data));
        var cipherBytes = asmCrypto.AES_CBC.encrypt(dataBytes, keyBytes, true, ivBytes);
        return { data: jodid25519.eddsa.bytes2string(cipherBytes),
                 iv: jodid25519.eddsa.bytes2string(ivBytes) };
    };


    /**
     * Decrypts a given data message.
     *
     * The data message is decrypted using AES-128-CBC.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @param iv {string}
     *     Binary string representation of 128-bit IV (initialisation vector).
     * @returns {string}
     *     The clear text message as a binary string.
     */
    ns.decryptDataMessage = function(data, key, iv) {
        if (data === null || data === undefined) {
            return null;
        }
        var keyBytes = new Uint8Array(jodid25519.eddsa.string2bytes(key));
        var ivBytes = new Uint8Array(jodid25519.eddsa.string2bytes(iv));
        var clearBytes = asmCrypto.AES_CBC.decrypt(data, keyBytes, true, ivBytes);
        // Undo protection for multi-byte characters.
        return decodeURIComponent(escape(jodid25519.eddsa.bytes2string(clearBytes)));
    };


    /**
     * Signs a given data message with the ephemeral private key.
     *
     * This implementation is using the Edwards25519 for an ECDSA signature
     * mechanism to complement the Curve25519-based group key agreement.
     *
     * @param data {string}
     *     Binary string data message.
     * @param privKey {string}
     *     Binary string representation of the ephemeral private key.
     * @param pubKey {string}
     *     Binary string representation of the ephemeral public key.
     * @returns {string}
     *     Binary string representation of the signature.
     */
    ns.signDataMessage = function(data, privKey, pubKey) {
        if (data === null || data === undefined) {
            return null;
        }
        return jodid25519.eddsa.signature(data, privKey, pubKey);
    };


    /**
     * Checks the signature of a given data message with the ephemeral public key.
     *
     * This implementation is using the Edwards25519 for an ECDSA signature
     * mechanism to complement the Curve25519-based group key agreement.
     *
     * @param data {string}
     *     Binary string data message.
     * @param signature {string}
     *     Binary string representation of the signature.
     * @param pubKey {string}
     *     Binary string representation of the ephemeral public key.
     * @returns {bool}
     *     True if the signature verifies, false otherwise.
     */
    ns.verifyDataMessage = function(data, signature, pubKey) {
        if (data === null || data === undefined) {
            return null;
        }
        return jodid25519.eddsa.checksig(signature, data, pubKey);
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

    return ns;
});
