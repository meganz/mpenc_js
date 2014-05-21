/**
 * @fileOverview
 * Some patches/enhancements to third party library modules.
 */

define([
    "mpenc/helper/utils",
    "curve255"
], function(utils, curve255) {
    "use strict";

    /**
     * @exports mpenc/helper/patches
     * Some patches/enhancements to third party library modules.
     *
     * @description
     * <p>Some patches/enhancements to third party library modules.</p>
     */
    var ns = {};

    /*
     * Created: 20 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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

    // Patches to the curve255.js namespace module.

    /**
     * Converts an 16-bit word element (unsigned) array a hex string representation.
     *
     * @param key
     *     The key as an 8 bit (unsigned) integer array.
     * @returns
     *     Hex string representation of key (big endian).
     * @private
     */
    curve255.toHex = function(key) {
        var out = '';
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            var remainder = 0;
            for (var j = 0; j < 4; j++) {
                remainder = value & 0x0f;
                out = utils._HEX_CHARS[remainder & 0x0f] + out;
                value = value >>> 4;
            }
        }
        return out;
    };


    /**
     * Converts a hex string to a 16-bit word element (unsigned) array representation.
     *
     * @param key
     *     Hex string representation of key (big endian).
     * @returns
     *     The key as an 16-bit word element (unsigned) integer array.
     * @private
     */
    curve255.fromHex = function(key) {
        var out = [];
        var padding = 4 - ((key.length & 3) || 4);
        for (var i = 0; i < padding; i++) {
            key = '0' + key;
        }
        var i = 0;
        while (i < key.length) {
            var value = 0;
            for (var j = 0; j < 4; j++) {
                value = (value << 4) | utils._HEX_CHARS.indexOf(key[i + j]);
            }
            out.unshift(value);
            i += 4;
        }
        return out;
    };


    /**
     * Converts an 16-bit word element (unsigned) array a binary string representation.
     *
     * @param key
     *     The key as an 16-bit word element (unsigned) integer array.
     * @returns
     *     Binary string representation of key (big endian).
     * @private
     */
    curve255.toString = function(key) {
        var out = '';
        for (var i = 0; i < key.length; i++) {
            var value = key[i];
            var remainder = 0;
            for (var j = 0; j < 2; j++) {
                remainder = value & 0xff;
                out = String.fromCharCode(remainder) + out;
                value = value >>> 8;
            }
        }
        return out;
    };


    /**
     * Converts a binary string to a 16-bit word element (unsigned) array representation.
     *
     * @param key
     *     Binary string representation of key (big endian).
     * @returns
     *     The key as an 16-bit word element (unsigned) integer array.
     * @private
     */
    curve255.fromString = function(key) {
        var out = [];
        var i = 0;
        if (key.length & 1) {
            key = '\u0000' + key;
        }
        while (i < key.length) {
            out.unshift((key.charCodeAt(i) << 8) | key.charCodeAt(i + 1));
            i += 2;
        }
        return out;
    };

    return ns;
});
