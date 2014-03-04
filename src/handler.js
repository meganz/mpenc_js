/**
 * @fileOverview
 * Implementation of a protocol handler with its state machine.
 */

"use strict";

/**
 * @namespace
 * Implementation of a protocol handler with its state machine.
 * 
 * @description
 * <p>Implementation of a protocol handler with its state machine.</p>
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
mpenc.handler = {};

/*
 * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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


