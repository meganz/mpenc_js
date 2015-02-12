/**
 * @fileOverview
 * Implementation of tools for tracking session-related information.
 */

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "megalogger",
], function(assert, utils, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/session
     * Implementation of tools for tracking session-related information.
     *
     * @description
     * <p>Implementation of tools for tracking session-related information.</p>
     *
     * <p>
     * The information tracked for the current and previous sessions is required
     * for the implemenation of trial decryption, ratchets, etc.</p>
     */
    var ns = {};

    var _assert = assert.assert;

    var logger = MegaLogger.getLogger('session', undefined, 'mpenc');

    /*
     * Created: 12 Feb 2015 Guy K. Kloss <gk@mega.co.nz>
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


    /**
     * A _SessionItem holds information of a specific session in the
     * {SessionTracker}.
     *
     * @constructor
     * @param sid {string}
     *     Session ID.
     * @param members {array}
     *     Array of {string}s of the participants for this session.
     * @param groupKey {string}
     *     The (first) group key used in this session.
     * @returns {module:mpenc/handler/_SessionItem}
     *
     * @property sid {string}
     *     Session ID.
     * @property members {array}
     *     Array of {string}s of the participants for this session.
     * @property groupKeys {array}
     *     Array of the group keys (as {string}) used in reverse order over this
     *     session (the last key is in the starting position).
     */
    var _SessionItem = function(sid, members, groupKey) {
        this.sid = sid;
        this.members = members;
        this.groupKeys = [groupKey];
    };

    /** @class
     * @see module:mpenc/handler#_SessionItem */
    ns._SessionItem = _SessionItem;


    /**
     * A SessionTracker holds information of different sessions encountered.
     *
     * <p>If the buffer goes above capacity, the oldest item is automatically
     * dropped without being tried again.</p>
     *
     * @constructor
     * @param name {string}
     *     Name for this tracker (e. g. the chat room name).
     * @param maxSizeFunc {maxSizeFunc}
     *     Function to determine the buffer capacity.
     * @param drop {boolean}
     *     Whether to drop items that overflow the buffer according to
     *     maxSizeFunc, or merely log a warning that the buffer is over
     *     capacity (optional, default: true).
     * @returns {module:mpenc/handler/SessionTracker}
     * @memberOf! module:mpenc/handler#
     *
     * @property name {string}
     *     Name of tracker.
     * @property maxSizeFunc {maxSizeFunc}
     *     Callback function to determine the max sizing of the buffer.
     * @property drop {boolean}
     *     Whether to drop elements beyond the sizing of the buffer.
     * @property sessions {object}
     *     Container of all {_SessionItem}s. The keys in the container are the
     *     session IDs of the (sub-) sessions.
     * @property sessionIDs {array}
     *     Array containing the reverse order of encountered session IDs
     *     (the latest one is at the first position).
     */
    var SessionTracker = function(name, maxSizeFunc, drop) {
        this.name = name || '';
        this.maxSizeFunc = maxSizeFunc;
        if (drop === undefined) {
            this.drop = true;
        } else {
            this.drop = drop;
        }
        this.sessions = {};
        // We're using this following array to keep the order within the
        // sessions in the buffer.
        this.sessionIDs = [];
    };

    /** @class
     * @see module:mpenc/handler#SessionTracker */
    ns.SessionTracker = SessionTracker;


    /**
     * Adds a new session object to the tracked sessions.
     *
     * @method
     * @param sid {string}
     *     Session ID.
     * @param members {array}
     *     Array of participants.
     * @param groupKey {string}
     *     Group key of the new session.
     */
    SessionTracker.prototype.addSession = function(sid, members, groupKey) {
        this.sessions[sid] = new _SessionItem(sid, members, groupKey);
        this.sessionIDs.unshift(sid);
        // Check for bufffer size overflow.
        var maxSize = this.maxSizeFunc();
        if (this.sessionIDs.length > maxSize) {
            if (this.drop) {
                var droppedID = this.sessionIDs.pop();
                var dropped = this.sessions[droppedID];
                delete this.sessions[droppedID];
                logger.warn(this.name + ' DROPPED session ' + droppedID +
                            ' at size ' + maxSize + ', potential data loss.');
            } else {
                logger.info(this.name + ' is '
                            + (this.sessionIDs.length - maxSize)
                            + ' items over expected capacity.');
            }
        }
    };


    /**
     * Adds a new group key to a stored session.
     *
     * @method
     * @param sid {string}
     *     Session ID to add the key to.
     * @param groupKey {string}
     *     New group key of the session.
     */
    SessionTracker.prototype.addGroupKey = function(sid, groupKey) {
        this.sessions[sid].groupKeys.unshift(groupKey);
    };


    /**
     * Adds a new group key to the most recent session.
     *
     * @method
     * @param groupKey {string}
     *     New group key of the session.
     */
    SessionTracker.prototype.addGroupKeyLastSession = function(groupKey) {
        var sid = this.sessionIDs[0];
        this.addGroupKey(sid, groupKey);
    };


    return ns;
});
