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
     * @param type
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
     * Encodes a given value to a binary TLV string of a given type.
     * 
     * @param type
     *     Type of string to use (16-bit unsigned integer).
     * @param value
     *     A binary string of the pay load to carry.
     * @returns
     *     A binary TLV string.
     */
    mpenc.codec.encodeTLV = function(type, value) {
        if (value === null) {
            value = '';
        }
        var out = mpenc.codec._short2bin(type);
        out += mpenc.codec._short2bin(value.length);
        return out + value;
    };

    
    /**
     * Encodes a given protocol message into a binary string message consisting
     * of a sequence of TLV binary strings.
     * 
     * @param message {mpenc.handler.ProtocolMessage}
     *     Type of string to use (16-bit unsigned integer).
     * @returns
     *     A binary message representation.
     */
    mpenc.codec.encodeMessage = function(message) {
//        if (value === null) {
//            value = '';
//        }
//        var out = mpenc.codec._short2bin(type);
//        out += mpenc.codec._short2bin(value.length);
        return null;
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