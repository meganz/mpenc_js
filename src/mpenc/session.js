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
    "mpenc/liveness",
    "mpenc/transcript",
    "mpenc/helper/struct",
], function(liveness, transcript, struct) {
    "use strict";

    /**
     * @exports mpenc/session
     * @description
     * Session processing and management.
     */
    var ns = {};

    var MsgReady      = transcript.MsgReady;
    var MsgFullyAcked = transcript.MsgFullyAcked;
    var NotAccepted   = liveness.NotAccepted;
    var NotFullyAcked = liveness.NotFullyAcked;

    var ImmutableSet = struct.ImmutableSet;


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
     * @enum {number}
     * @memberOf module:mpenc/session
     */
    var SessionState = {
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
    ns.SessionState = SessionState;

    /**
     * Things that can happen to a Session.
     *
     * **API WARNING**: currently `SNState` is never emitted by any `Session`;
     * clients should not rely on that yet.
     *
     * @interface
     * @memberOf module:mpenc/session
     * @see module:mpenc/session.Session#onRecv
     * @see module:mpenc/session.SNState
     * @see module:mpenc/session.SNMembers
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
     * When the session state changes.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNState = struct.createTupleClass("SNState", "newState oldState");

    ns.SNState = SNState;


    /**
     * When the session membership changes.
     *
     * Emitted by {@link module:mpenc/session.Session}.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNMembers = struct.createTupleClass("SNMembers", "remain include exclude parents");

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Previous membership set.
     */
    SNMembers.prototype.prevMembers = function() {
        return this.remain.union(this.exclude);
    };

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Current membership set.
     */
    SNMembers.prototype.members = function() {
        return this.remain.union(this.include);
    };

    SNMembers.prototype._postInit = function() {
        if (!this.remain.size) {
            throw new Error("tried to create SNMembers without an owner member");
        }
        if (!this.include.size && !this.exclude.size) {
            throw new Error("tried to create SNMembers with empty membership change; remain: " +
                this.remain.toArray());
        }
        if (!struct.isDisjoint(this.remain, this.include, this.exclude)) {
            throw new Error("tried to create SNMembers with contradictory membership change");
        }
        if (!(this.parents instanceof ImmutableSet)) {
            throw new Error("SNMembers.parents must be an ImmutableSet");
        }

    };

    ns.SNMembers = SNMembers;

    /** @alias module:mpenc/transcript.MsgReady */
    ns.MsgReady = transcript.MsgReady;

    /** @alias module:mpenc/transcript.MsgFullyAcked */
    ns.MsgFullyAcked = transcript.MsgFullyAcked;

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
    var NotDecrypted = struct.createTupleClass("NotDecrypted", "context sender size");

    ns.NotDecrypted = NotDecrypted;

    /** @alias module:mpenc/liveness.NotAccepted */
    ns.NotAccepted = liveness.NotAccepted;

    /** @alias module:mpenc/liveness.NotFullyAcked */
    ns.NotFullyAcked = liveness.NotFullyAcked;


    /**
     * Try to do something to/on the cryptographic logical session.
     *
     * <p>One may use {@link module:mpenc/session.checkSessionAction
     * checkSessionAction} to check valid values.</p>
     *
     * @typedef {Object} SessionAction
     * @property [content] {string} Message to send, or if empty then send
     *      an explicit ack. If this is set, other properties must not be set.
     * @property [join] {boolean} Include all others into our session. This
     *      is everyone else that is currently in the group transport channel.
     *      If this is set, other properties must not be set.
     * @property [part] {boolean} Exclude all others from our session. These
     *      members will also be made to leave the group transport channel.
     *      If this is set, other properties must not be set.
     * @property [include] {module:mpenc/helper/struct.ImmutableSet} Other
     *      members to try to include into the session. If this is set, only
     *      <code>exclude</code> may also be set.
     * @property [exclude] {module:mpenc/helper/struct.ImmutableSet} Other
     *      members to try to exclude from the session. If this is set, only
     *      <code>include</code> may also be set.
     */

    /**
     * @param act {module:mpenc/session~SessionAction} Action to check.
     * @return {module:mpenc/session~SessionAction} Validated action, maybe
     *      with canonicalised values.
     * @throws If the action was not valid and could not be canonicalised.
     */
    ns.checkSessionAction = function(act) {
        var hasContent = "content" in act;
        var hasJoin = "join" in act;
        var hasPart = "part" in act;
        var hasMemChg = "include" in act || "exclude" in act;
        if (0 + hasContent + hasMemChg + hasJoin + hasPart !== 1) {
            throw new Error("tried to create SessionAction with conflicting properties");
        }
        if (hasContent) {
            if (typeof act.content !== "string") {
                throw new Error("tried to create SessionAction with non-string content");
            }
        } else if (hasJoin) {
            if (act.join !== true) {
                throw new Error("tried to create SessionAction with non-true join");
            }
        } else if (hasPart) {
            if (act.part !== true) {
                throw new Error("tried to create SessionAction with non-true part");
            }
        } else {
            var include = ImmutableSet.from(act.include);
            var exclude = ImmutableSet.from(act.exclude);
            if (!include.size && !exclude.size) {
                throw new Error("tried to create SessionAction with empty membership change");
            }
            if (!struct.isDisjoint(include, exclude)) {
                throw new Error("tried to create SessionAction with contradictory membership change");
            }
            return { include: include, exclude: exclude };
        }
        return act;
    };


    /**
     * An ongoing communication session, from the view of a given member.
     *
     * <p>A session is a logical entity tied to a member ("owner"), who performs
     * operations on their view of the membership set. It has no existence
     * outside of a member's conception of it - c.f. a group transport channel,
     * where a server keeps it "existing" even if nobody is in it.</p>
     *
     * <p>Hence, <code>this.curMembers().has(this.owner())</code> always returns
     * <code>true</code>. Moreover, joining or parting another session is
     * viewed as the other members being included into or excluded from a local
     * 1-member session, as reflected in SNMembers.</p>
     *
     * The instantiated types for <code>ReceivingExecutor</code> are:
     *
     * <ul>
     * <li><code>{@link module:mpenc/session.Session#send|SendInput}</code>:
     *      {@link module:mpenc/session~SessionAction}.</li>
     * <li><code>{@link module:mpenc/session.Session#onRecv|RecvOutput}</code>:
     *      {@link module:mpenc/session.SessionNotice}</li>
     * </ul>
     *
     * Additionally, the upper layer may subscribe to particular subsets of
     * what <code>onRecv()</code> publishes, using <code>{@link
     * module:mpenc/session.Session#onEvent|onEvent}</code>.
     *
     * <p>Implementations <em>need not</em> define <code>execute()</code> for
     * when the input has a <code>content</code> property, but they <strong>
     * must</strong> define it for {@link module:mpenc/session~SessionAction
     * all other values}.</p>
     *
     * @interface
     * @augments module:mpenc/helper/utils.ReceivingExecutor
     * @augments module:mpenc/helper/async.EventSource
     * @memberOf module:mpenc/session
     */
    var Session = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * Array containing the events types that this `EventSource` can publish.
     * For Session, this is just all the child classes of `SessionNotice`.
     *
     * @memberOf module:mpenc/session.Session
     * @see module:mpenc/session.SessionNotice
     */
    Session.EventTypes = [SNState, SNMembers,
                          MsgReady, MsgFullyAcked,
                          NotDecrypted, NotAccepted, NotFullyAcked];

    /**
     * @method
     * @returns {string} Session id, shared between all members.
     */
    Session.prototype.sessionId;

    /**
     * @method
     * @returns {string}
     *      The user id of the owner of this process, that authors messages.
     */
    Session.prototype.owner;

    /**
     * @method
     * @returns {module:mpenc/transcript.MessageLog}
     *      Payload messages belonging to this session.
     */
    Session.prototype.messages;

    /**
     * **API WARNING**: the behaviour of this is currently experimental;
     * clients should not rely on this yet.
     *
     * @method
     * @returns {module:mpenc/session.SessionState} Current state of this session.
     */
    Session.prototype.state;

    /**
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} The current session
     *      membership. In some cases, the membership of some recent messages
     *      may differ from this, such as during a membership operation. Any UI
     *      should be able to detect this and display this accordingly.
     */
    Session.prototype.curMembers;

    /**
     * @method
     * @returns {boolean} Whether there are any unacked Payload messages.
     */
    Session.prototype.isConsistent;

    ns.Session = Session;
    // jshint +W030


    return ns;
});
