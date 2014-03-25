/**
 * @fileOverview
 * Implementation of a protocol encoder/decoder.
 */

(function() {
    "use strict";

    /**
     * @namespace
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
    mpenc.codec = {};
    
    var _assert = mpenc.assert.assert;
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
     * "Enumeration" for TLV types.
     * 
     * @property PADDING
     *     Can be used for arbitrary length of padding byte sequences.
     * @property PROTOCOL_VERSION
     *     Indicates the protocol version to be used as a 16-bit unsigned integer.
     * @property MESSAGE_TYPE
     *     A single byte indicating the type of message transmitted.
     * @property SOURCE
     *     Message originator (from, should be only one).
     * @property DEST
     *     Message destination (to, should be only one, broadcast if not present).
     * @property AUX_AGREEMENT
     *     Type of key agreement. 0 for "initial" or 1 for "auxilliary".
     * @property MEMBER
     *     A participating member ID.
     * @property INT_KEY
     *     An intermediate key for the group key agreement (max occurrence is 
     *     the number of members present).
     * @property NONCE
     *     A nonce of a member for ASKE (max occurrence is the number of 
     *     members present).
     * @property PUB_KEY
     *     Ephemeral public signing key of a member (max occurrence is the 
     *     number of members present).
     * @property SESSION_SIGNATURE
     *     Session acknowledgement signature using sender's static key.
     */
    mpenc.codec.TLV_TYPES = {
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
    };
    
    
    /**
     * "Enumeration" message types.
     * 
     * FIXME: This needs some serious work.
     * 
     * @property DATA
     *     Used to transmit a private message.
     */
    mpenc.codec.MESSAGE_TYPES = {
        DATA:              0x03,
        KEY_AGREEMENT:     0x0a,
        REVEAL_SIGNATURE:  0x11,
        SIGNATURE:         0x12,
    };
    
    
    /**
     * Decodes a given binary TVL string to a type and value.
     * 
     * @param tlv
     *     A binary TLV string.
     * @returns {Object}
     *     An object containing the type of string (in `type`, 16-bit unsigned
     *     integer) and the value (in `value`, binary string of the pay load).
     *     left over bytes from the input are returned in `rest`.
     */
    mpenc.codec.decodeTLV = function(tlv) {
        var length = mpenc.codec._bin2short(tlv.substring(2, 4));
        var value = tlv.substring(4, 4 + length);
        _assert(length === value.length,
                'TLV payload length does not match indicated length.');
        if (value.length === 0) {
            value = null;
        }
        return {
            type: mpenc.codec._bin2short(tlv.substring(0, 2)),
            value: value,
            rest: tlv.substring(length + 4)
        };
    };

    
    /**
     * Decodes a given TLV encoded protocol message content into an object.
     * 
     * @param message
     *     A binary message representation.
     * @returns {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     */
    mpenc.codec.decodeMessageContent = function(message) {
        var out = new mpenc.handler.ProtocolMessage();
        
        // members, intKeys, nonces, pubKeys, sessionSignature
        while (message.length > 0) {
            var tlv = mpenc.codec.decodeTLV(message);
            switch (tlv.type) {
                case mpenc.codec.TLV_TYPES.SOURCE:
                    out.source = tlv.value;
                    break;
                case mpenc.codec.TLV_TYPES.DEST:
                    out.dest = tlv.value;
                    if ((out.dest === '') || (out.dest === null)) {
                        out.flow = 'downflow';
                    } else {
                        out.flow = 'upflow';
                    }
                    break;
                case mpenc.codec.TLV_TYPES.AUX_AGREEMENT:
                    if (tlv.value === _ZERO_BYTE) {
                        out.agreement = 'initial';
                    } else if (tlv.value === _ONE_BYTE) {
                        out.agreement = 'auxilliary';
                    } else {
                        _assert(false, 'Unexpected value for agreement TLV: ' + tlv.value + '.');
                    }
                    break;
                case mpenc.codec.TLV_TYPES.MEMBER:
                    out.members.push(tlv.value);
                    break;
                case mpenc.codec.TLV_TYPES.INT_KEY:
                    out.intKeys.push(tlv.value);
                    break;
                case mpenc.codec.TLV_TYPES.NONCE:
                    out.nonces.push(tlv.value);
                    break;
                case mpenc.codec.TLV_TYPES.PUB_KEY:
                    out.pubKeys.push(tlv.value);
                    break;
                case mpenc.codec.TLV_TYPES.SESSION_SIGNATURE:
                    out.sessionSignature = tlv.value;
                    break;
                default:
                    _assert(false, 'Received unknown TLV type.');
                    break;
            }
            
            // Some sanity checks.
            _assert(out.intKeys.length <= out.members.length,
                    'Number of intermediate keys cannot exceed number of members.');
            _assert(out.nonces.length <= out.members.length,
                    'Number of nonces cannot exceed number of members.');
            _assert(out.pubKeys.length <= out.members.length,
                    'Number of public keys cannot exceed number of members.');
    
            message = tlv.rest;
        }
        
        return out;
    };

    
    /**
     * Decodes a given wire protocol message content into an object.
     * 
     * @param message
     *     A wire protocol message representation.
     * @returns {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     */
    mpenc.codec.decodeMessage = function(message) {
        if (message === null || message === undefined) {
            return null;
        }
        _assert(message.substring(0, _PROTOCOL_PREFIX.length) === _PROTOCOL_PREFIX,
                'Not an understood protocol/version.');
        message = message.substring(_PROTOCOL_PREFIX.length);
        _assert(message[0] === ':',
                'Incomprehensible protocol indication.');
        _assert(message[message.length - 1] === '.',
                'Invalid protocol message format.');
        var payload = atob(message.substring(1, message.length - 1));
        
        return mpenc.codec.decodeMessageContent(payload);
    };

    
    /**
     * Encodes a given value to a binary TLV string of a given type.
     * 
     * @param tlvType
     *     Type of string to use (16-bit unsigned integer).
     * @param value
     *     A binary string of the pay load to carry.
     * @returns
     *     A binary TLV string.
     */
    mpenc.codec.encodeTLV = function(tlvType, value) {
        if (value === null) {
            value = '';
        }
        var out = mpenc.codec._short2bin(tlvType);
        out += mpenc.codec._short2bin(value.length);
        return out + value;
    };

    
    /**
     * Encodes an array of values to a binary TLV string of a given type.
     * 
     * @param tlvType
     *     Type of string to use (16-bit unsigned integer).
     * @param valueArray
     *     The array of values.
     * @returns
     *     A binary TLV string.
     */
    mpenc.codec._encodeTlvArray = function(tlvType, valueArray) {
        _assert((valueArray instanceof Array) || (valueArray === null),
                'Value passed neither an array or null.');
        
        // Trivial case, quick exit.
        if ((valueArray === null) || (valueArray.length === 0)) {
            return '';
        }
        
        var out = '';
        for (var i = 0; i < valueArray.length; i++) {
            out += mpenc.codec.encodeTLV(tlvType, valueArray[i]);
        }
        return out;
    };

    
    /**
     * Encodes a given protocol message content into a binary string message
     * consisting of a sequence of TLV binary strings.
     * 
     * @param message {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     * @returns
     *     A binary message representation.
     */
    mpenc.codec.encodeMessageContent = function(message) {
        // Process message attributes in this order:
        // source, dest, agreement, members, intKeys, nonces, pubKeys, sessionSignature
        
        var out = mpenc.codec.encodeTLV(mpenc.codec.TLV_TYPES.SOURCE, message.source);
        out += mpenc.codec.encodeTLV(mpenc.codec.TLV_TYPES.DEST, message.dest);
        if (message.agreement === 'initial') {
            out += mpenc.codec.encodeTLV(mpenc.codec.TLV_TYPES.AUX_AGREEMENT, _ZERO_BYTE);
        } else {
            out += mpenc.codec.encodeTLV(mpenc.codec.TLV_TYPES.AUX_AGREEMENT, _ONE_BYTE);
        }
        out += mpenc.codec._encodeTlvArray(mpenc.codec.TLV_TYPES.MEMBER, message.members);
        out += mpenc.codec._encodeTlvArray(mpenc.codec.TLV_TYPES.INT_KEY, message.intKeys);
        out += mpenc.codec._encodeTlvArray(mpenc.codec.TLV_TYPES.NONCE, message.nonces);
        out += mpenc.codec._encodeTlvArray(mpenc.codec.TLV_TYPES.PUB_KEY, message.pubKeys);
        out += mpenc.codec.encodeTLV(mpenc.codec.TLV_TYPES.SESSION_SIGNATURE, message.sessionSignature);
        
        return out;
    };

    
    /**
     * Encodes a given protocol message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     * 
     * @param message {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     * @returns
     *     A wire ready message representation.
     */
    mpenc.codec.encodeMessage = function(message) {
        if (message === null || message === undefined) {
            return null;
        }
        var content = mpenc.codec.encodeMessageContent(message);
        return _PROTOCOL_PREFIX + ':' + btoa(content) + '.';
    };
    
    
    /**
     * Converts an unsigned short integer to a binary string.
     * 
     * @param value
     *     A 16-bit unsigned integer.
     * @returns
     *     A two character binary string.
     */
    mpenc.codec._short2bin = function(value) {
        return String.fromCharCode(value >> 8) + String.fromCharCode(value % 256);
    };
    
    
    /**
     * Converts a binary string to an unsigned short integer.
     * 
     * @param value
     *     A two character binary string.
     * @returns
     *     A 16-bit unsigned integer.
     */
    mpenc.codec._bin2short= function(value) {
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
    mpenc.codec.encryptDataMessage = function(data, key) {
        if (data === null || data === undefined) {
            return null;
        }
        var clearBytes = new Uint8Array(djbec.string2bytes(data));
        var keyBytes = new Uint8Array(djbec.string2bytes(key));
        var ivBytes = new Uint8Array(mpenc.utils._newKey08(128));
        var cipherBytes = asmCrypto.AES_CBC.encrypt(clearBytes, keyBytes, true, ivBytes);
        return { data: djbec.bytes2string(cipherBytes),
                 iv: djbec.bytes2string(ivBytes) };
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
    mpenc.codec.decryptDataMessage = function(data, key, iv) {
        if (data === null || data === undefined) {
            return null;
        }
        var cipherBytes = new Uint8Array(djbec.string2bytes(data));
        var keyBytes = new Uint8Array(djbec.string2bytes(key));
        var ivBytes = new Uint8Array(djbec.string2bytes(iv));
        var clearBytes = asmCrypto.AES_CBC.decrypt(cipherBytes, keyBytes, true, ivBytes);
        return djbec.bytes2string(clearBytes);
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
    mpenc.codec.signDataMessage = function(data, privKey, pubKey) {
        if (data === null || data === undefined) {
            return null;
        }
        
        var pubKeyBytes = djbec.string2bytes(pubKey);
        var signatureBytes = djbec.signature(data, privKey, pubKeyBytes);
        return djbec.bytes2string(signatureBytes);
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
    mpenc.codec.verifyDataMessage = function(data, signature, pubKey) {
        if (data === null || data === undefined) {
            return null;
        }
        
        var pubKeyBytes = djbec.string2bytes(pubKey);
        var signatureBytes = djbec.string2bytes(signature);
        return signatureBytes = djbec.checksig(signatureBytes, data, pubKeyBytes);
    };
    
    // TODO: message wrapping like OTR:
    // * message message: "?mpENC:{content}."
    // * proto query/request: "?mpENCv1?" (anywhere in message to express willingness to use mpENCvX, or re-establish mpENCvX session)
    
})();
