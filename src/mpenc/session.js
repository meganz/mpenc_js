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
     * Things that can happen to a Session.
     *
     * @interface
     * @memberOf module:mpenc/session
     * @see module:mpenc/session.Session#onRecv
     * @see module:mpenc/session.SNStateChange
     * @see module:mpenc/session.SNInclude
     * @see module:mpenc/session.SNExclude
     * @see module:mpenc/transcript.MsgReady
     * @see module:mpenc/transcript.MsgFullyAcked
     * @see module:mpenc/session.NotDecrypted
     * @see module:mpenc/liveness.NotAccepted
     * @see module:mpenc/liveness.NotFullyAcked
     */
    var SessionNotice = function() {
        throw new Error("cannot instantiate an interface");
    };

    SessionNotice.prototype = Object.create(Array.prototype);

    ns.SessionNotice = SessionNotice;


    /**
     * State of the logical session.
     *
     * <p>Logical means based on the logical cryptographic membership operations
     * that have thus far been accepted as part of the session history - e.g. we
     * are still JOINED even if the transport is disconnected.</p>
     *
     * <pre>
     *            can send    can recv
     * JOINED          1           1
     * PARTING         0           1
     * PART_FAILED     0           1
     * PARTED          0           0 (except for join requests / attempts)
     * JOINING         0           1
     * JOIN_FAILED     0           1
     * ERROR           0           0
     * </pre>
     *
     * Note: JOINING and JOIN_FAILED are not currently used, pending further
     * research into a fully causally-ordered transcript history that also
     * supports partial visibility.
     *
     * @enum {number}
     * @memberOf module:mpenc/session
     */
    ns.SessionState = {
        /** We have joined the session and are ready to send messages. */
        JOINED       : 1,
        /** We will no longer send messages and have begun parting the session. */
        PARTING      : 2,
        /** Parting failed, e.g. due to inconsistency. */
        PART_FAILED  : 3,
        /** We have parted the session and will no longer receive/accept messages. */
        PARTED       : 4,
        /** We have begun to receive/accept messages and have begun re-joining the session. */
        JOINING      : 5,
        /** Joining failed, e.g. due to inconsistency. */
        JOIN_FAILED  : 6,
        /** A fatal error was detected and added to the transcript. */
        ERROR        : 7
    };

    /**
     * When the session state changes.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNStateChange = struct.createTupleClass(SessionNotice, "newState", "oldState");

    ns.SNStateChange = SNStateChange;


    /**
     * When some users are included into our session.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNInclude = struct.createTupleClass(SessionNotice, "us", "others");

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Previous membership set.
     */
    SNInclude.prototype.prevMembers = function() {
        return this.us;
    };

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Current membership set.
     */
    SNInclude.prototype.members = function() {
        return this.us.union(this.others);
    };

    ns.SNInclude = SNInclude;


    /**
     * When some users are excluded from our session.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNExclude = struct.createTupleClass(SessionNotice, "us", "others");

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Previous membership set.
     */
    SNExclude.prototype.prevMembers = function() {
        return this.us.union(this.others);
    };

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Current membership set.
     */
    SNExclude.prototype.members = function() {
        return this.us;
    };

    ns.SNExclude = SNExclude;


    /**
     * A packet has not yet been verify-decrypted, even after a grace period.
     *
     * This is probably due to the transport being unreliable (previous messages
     * containing secrets not yet received), but could also be due to a malicious
     * transport, malicious outsiders, or a malicious or buggy sender; and the
     * message has been ignored.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var NotDecrypted = struct.createTupleClass(NotDecrypted, "context", "sender", "size");

    ns.NotDecrypted = NotDecrypted;


    /**
     * XXX: TODO: import doc from python, with some tweaks.
     *
     * @interface
     * @augments module:mpenc/helper/utils.SendingReceiver
     * @augments module:mpenc/helper/utils.ReceivingExecutor
     * @memberOf module:mpenc/session
     */
    var Session = function() {
        throw new Error("cannot instantiate an interface");
    };

    ns.Session = Session;


    return ns;
});
