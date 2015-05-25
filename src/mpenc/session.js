/*
 * Created: 02 Jun 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/helper/struct",
    "megalogger"
], function(struct, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/session
     * @description
     * Session processing and management.
     */
    var ns = {};

    /**
     * State of the logical session.
     * Logical means based on the logical cryptographic membership operations that
     * have thus far been accepted as part of the session history - e.g. we are
     * still JOINED even if the transport is disconnected.

     *            can send    can recv
     * JOINED          1           1
     * PARTING         0           1
     * PART_FAILED     0           1
     * PARTED          0           0 (except for join requests / attempts)
     * JOINING         0           1
     * JOIN_FAILED     0           1

     * ERROR           0           0

     * TODO(xl): [R] elaborate what "joining" means in terms of waiting for a sync
     * point (i.e. LCA of other members' latest messages is visible to us).

     * TODO(xl): [R] decide/clarify whether "can send" means manual or all (i.e.
     * including automatic flow control) messages.

     * TODO(xl): [R] make SessionBase/*Session actually use the other states, e.g.
     * ERROR (invalid-msg), JOINING (full-causal)
     */
    ns.SessionState = {
        JOINED       : 1,
        PARTING      : 2,
        PART_FAILED  : 3,
        PARTED       : 4,
        JOINING      : 5,
        JOIN_FAILED  : 6,
        ERROR        : 7
    };

    /**
     * When the session state changes.
     * Attributes:
     *  new: New (current) state.
     *  old: Old state, a SessionState enum member.
     */
    var SNStateChange = struct.createTupleClass("newState", "oldState");

    ns.SNStateChange = SNStateChange;


    return ns;
});
