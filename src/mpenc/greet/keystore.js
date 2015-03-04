/**
 * @fileOverview
 * Implementation of tools for storing session-related key information.
 */

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "mpenc/helper/struct",
    "megalogger",
], function(assert, utils, struct, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/greet/keystore
     * Implementation of tools for storing session-related key information.
     *
     * @description
     * <p>Implementation of tools for storing session-related key information.
     * </p>
     *
     * <p>
     * The information stored for the current and previous sessions is required
     * for the implementation of trial decryption, ratchets, etc.</p>
     */
    var ns = {};

    var _assert = assert.assert;

    var logger = MegaLogger.getLogger('keystore', undefined, 'greet');

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
     * A _SessionItem holds information of a specific session in the {KeyStore}.
     *
     * @constructor
     * @param members {array<string>}
     *     Array of the participant IDs for this session.
     * @param groupKey {string}
     *     The (first) group key used in this session.
     * @returns {module:mpenc/greet/keystore._SessionItem}
     *
     * @property members {array<string>}
     *     Array of the participant IDs for this session.
     * @property groupKeys {array<string>}
     *     Array of the group keys used in reverse order over this session
     *     (the last key is in the starting position).
     */
    var _SessionItem = function(members, groupKey) {
        this.members = members;
        this.groupKeys = [groupKey];
    };

    /** @class
     * @see module:mpenc/greet/keystore#_SessionItem */
    ns._SessionItem = _SessionItem;


    /**
     * A KeyStore holds key information of different (sub-) sessions
     * encountered.
     *
     * <p>If the buffer goes above capacity, the oldest item is automatically
     * dropped without being tried again.</p>
     *
     * @constructor
     * @param name {string}
     *     Name for this store (e. g. the chat room name).
     * @param maxSizeFunc {maxSizeFunc}
     *     Function to determine the buffer capacity.
     * @param drop {boolean}
     *     Whether to drop items that overflow the buffer according to
     *     maxSizeFunc, or merely log a warning that the buffer is over
     *     capacity (optional, default: true).
     * @returns {module:mpenc/greet/keystore.KeyStore}
     * @memberOf! module:mpenc/greet/keystore#
     *
     * @property name {string}
     *     Name of store.
     * @property maxSizeFunc {maxSizeFunc}
     *     Callback function to determine the max sizing of the buffer.
     * @property drop {boolean}
     *     Whether to drop elements beyond the sizing of the buffer.
     * @property sessions {object}
     *     Container of all {_SessionItem}s. The keys in the container are the
     *     session IDs of the (sub-) sessions.
     * @property sessionIDs {array<string>}
     *     Array containing the reverse order of encountered session IDs
     *     (the latest one is at the first position).
     * @property pubKeyMap {object}
     *     An object that maps participant IDs to ephemeral public signing keys.
     */
    var KeyStore = function(name, maxSizeFunc, drop) {
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
        this.pubKeyMap = {};
    };

    /** @class
     * @see module:mpenc/greet/keystore#KeyStore */
    ns.KeyStore = KeyStore;


    /**
     * Adds a new session object to the key store.
     *
     * @method
     * @param sid {string}
     *     Session ID.
     * @param members {array<string>}
     *     Participant IDs.
     * @param pubKeys {array<string>}
     *     Participants' ephemeral public signing keys.
     * @param groupKey {string}
     *     Group key of the new session.
     */
    KeyStore.prototype.addSession = function(sid, members, pubKeys, groupKey) {
        if (this.sessionIDs.indexOf(sid) >= 0) {
            var message = 'Attempt to add a session with an already existing ID on '
                        + this.name + '.';
            logger.error(message);
            throw new Error(message)
        }

        this.sessions[sid] = new _SessionItem(members, groupKey);
        this.sessionIDs.unshift(sid);
        // Add pubKeys to our internal map.
        _assert(members.length === pubKeys.length,
                'Length of members/pub keys mismatch.');
        for (var i in members) {
            if (this.pubKeyMap.hasOwnProperty(members[i])) {
                _assert(this.pubKeyMap[members[i]] === pubKeys[i],
                        'Ephemeral public signing key of member ' + members[i] + 'mismatch.');
            } else {
                this.pubKeyMap[members[i]] = pubKeys[i];
            }
        }
        // Check for buffer size overflow.
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
    KeyStore.prototype.addGroupKey = function(sid, groupKey) {
        if (this.sessions[sid].groupKeys.indexOf(groupKey) >= 0) {
            logger.info(this.name
                        + ' ignores adding a group key already stored.');
        } else {
            this.sessions[sid].groupKeys.unshift(groupKey);
            if (this.sessionIDs.indexOf(sid) > 0) {
                // Not the most current session.
                logger.warn('New group key added to non-current session on '
                            + this.name + '.');
            }
        }
    };


    /**
     * Adds a new group key to the most recent session.
     *
     * @method
     * @param groupKey {string}
     *     New group key of the session.
     */
    KeyStore.prototype.addGroupKeyLastSession = function(groupKey) {
        var sid = this.sessionIDs[0];
        this.addGroupKey(sid, groupKey);
    };


    /**
     * Updates the store with the new given session information. If the
     * session ID is previously unknown, a new {_SessionItem} will be added,
     * otherwise only the new group key will be added.
     *
     * @method
     * @param sid {string}
     *     Session ID.
     * @param members {array<string>}
     *     Array of participants.
     * @param pubKeys {array<string>}
     *     Participants' ephemeral public signing keys.
     * @param groupKey {string}
     *     Group key of the session.
     * @throws
     *     Error if the participants list mismatches for an existing session ID.
     */
    KeyStore.prototype.update = function(sid, members, pubKeys, groupKey) {
        if (this.sessionIDs.indexOf(sid) >= 0) {
            // Session already stored.
            _assert(struct.ImmutableSet(members)
                    .equals(struct.ImmutableSet(this.sessions[sid].members)),
                    'Attempt to update ' + this.name
                    + ' with mis-matching members for a sesssion.')
            this.addGroupKey(sid, groupKey);
        } else {
            this.addSession(sid, members, pubKeys, groupKey);
        }
    };


    return ns;
});
