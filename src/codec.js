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
        SOURCE:            0x0100,
        DEST:              0x0101,
        AUX_AGREEMENT:     0x0102,
        MEMBER:            0x0103,
        INT_KEY:           0x0104,
        NONCE:             0x0105,
        PUB_KEY:           0x0106,
        SESSION_SIGNATURE: 0x0107
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
     * Decodes a given TLV encoded protocol message into an object.
     * 
     * @param message
     *     A binary message representation.
     * @returns {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     */
    mpenc.codec.decodeMessage = function(message) {
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
                    if (out.dest === '') {
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
            return mpenc.codec.encodeTLV(tlvType, null);
        }
        
        var out = '';
        for (var i = 0; i < valueArray.length; i++) {
            out += mpenc.codec.encodeTLV(tlvType, valueArray[i]);
        }
        return out;
    };

    
    /**
     * Encodes a given protocol message into a binary string message consisting
     * of a sequence of TLV binary strings.
     * 
     * @param message {mpenc.handler.ProtocolMessage}
     *     Message as JavaScript object.
     * @returns
     *     A binary message representation.
     */
    mpenc.codec.encodeMessage = function(message) {
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
})();
