/**
 * @fileOverview JavaScript mpEnc implementation.
 */

/*
 * Created: 11 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

"use strict";

/**
 * @namespace
 * The multi-party encrypted chat protocol, top-level namespace.
 *
 * @description
 * This is eventually to be extended towards the mpOTR standard, currently
 * under development.
 */
define([
    "exports",
], function(exports) {

    var mpenc = {};

    /** Protocol version indicator. */
    mpenc.VERSION = String.fromCharCode(0x01);

    exports.VERSION = mpenc.VERSION;

    return mpenc;
});
