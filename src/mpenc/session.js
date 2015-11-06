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
    "mpenc/helper/assert",
], function(struct, assert) {
    "use strict";

    /**
     * @exports mpenc/session
     * @description
     * Session processing and management.
     */
    var ns = {};

    var ImmutableSet = struct.ImmutableSet;

    var _assert = assert.assert;


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
     * Things that can happen in a Session. Specifically, this can be one of:
     *
     * - {@link module:mpenc/session.SNState} (not yet implemented)
     * - {@link module:mpenc/session.SNMembers}
     * - {@link module:mpenc/session.MsgReady}
     * - {@link module:mpenc/session.MsgFullyAcked}
     * - {@link module:mpenc/session.NotFullyAcked}
     * - {@link module:mpenc/session.NotDecrypted} (optional)
     * - {@link module:mpenc/session.NotAccepted} (optional)
     *
     * **API WARNING**: currently `SNState` is never emitted by any `Session`;
     * clients should not expect to see these events yet.
     *
     * `SessionNotice` events are all implicitly associated with a `Session`.
     * They do not contain an *explicit* reference to it, because this is not
     * necessary - in order to receive one of these objects, you need to have
     * registered your callback using `Session.onRecv` or `Session.onEvent`,
     * which means you must already have a reference to its session.
     *
     * @interface
     * @memberOf module:mpenc/session
     * @see module:mpenc/session.Session#onRecv
     * @see module:mpenc/session~SessionAction
     */
    var SessionNotice = function() {
        throw new Error("cannot instantiate an interface");
    };

    SessionNotice.prototype = Object.create(Array.prototype);

    ns.SessionNotice = SessionNotice;


    /**
     * The session state has changed.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var SNState = struct.createTupleClass("SNState", "newState oldState");

    ns.SNState = SNState;


    /**
     * The session membership has changed.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property remain {module:mpenc/helper/struct.ImmutableSet}
     *      The older members that still remain in the current session.
     * @property include {module:mpenc/helper/struct.ImmutableSet}
     *      The newer members included into the current session.
     * @property exclude {module:mpenc/helper/struct.ImmutableSet}
     *      The older members excluded from the current session.
     * @memberOf module:mpenc/session
     */
    var SNMembers = struct.createTupleClass("SNMembers", "remain include exclude parents");

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     *      The older members, i.e. `remain | exclude`.
     */
    SNMembers.prototype.prevMembers = function() {
        return this.remain.union(this.exclude);
    };

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     *      The current nemmbers, i.e. `remain | include`.
     */
    SNMembers.prototype.members = function() {
        return this.remain.union(this.include);
    };

    /**
     * @returns {boolean} Whether this event represents joining a session.
     */
    SNMembers.prototype.isJoin = function() {
        return this.remain.size === 1 && this.include.size && !this.exclude.size;
    };

    /**
     * @returns {boolean} Whether this event represents parting a session.
     */
    SNMembers.prototype.isPart = function() {
        return this.remain.size === 1 && !this.include.size && this.exclude.size;
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

    /**
     * A message has been accepted into a Transcript.
     *
     * @class
     * @private
     * @property mId {string} The message id.
     * @memberOf module:mpenc/session
     */
    var MsgAccepted = struct.createTupleClass("MsgAccepted", "mId");

    Object.freeze(MsgAccepted.prototype);
    ns.MsgAccepted = MsgAccepted;

    /**
     * A message has been acknowledged by all of its intended readers.
     *
     * When you receive this event, you may unconditionally remove any warnings
     * that you previously added in response to the lack of this event, e.g.
     * when handling `NotFullyAcked`.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property mId {string} The message id.
     * @memberOf module:mpenc/session
     */
    var MsgFullyAcked = struct.createTupleClass("MsgFullyAcked", "mId");

    Object.freeze(MsgFullyAcked.prototype);
    ns.MsgFullyAcked = MsgFullyAcked;

    /**
     * A message is ready to be consumed by the higher-layer client.
     *
     * The client may see messages that have a membership *different* from the
     * current session membership (e.g. because the author wrote it before
     * *they* saw the membership change). The client *must* highlight messages
     * where this is the case, otherwise the user could severely misunderstand
     * the situation.
     *
     * The first event emitted will have `rIdx: 0, parents: {}`.
     *
     * For subsequent events, the client *should* highlight (e.g. in the UI)
     * cases where `parents` is not `{1}`. Furthermore, if `rIdx` is not `0`,
     * then the client will also need to re-evaluate whether to highlight the
     * message after which this one was inserted, and perhaps all re-render all
     * subsequent messages if this is necessary.
     *
     * (Lazy clients for now can just `assert(rIdx === 0)` since our system
     * currently only emits `0` values. But in the future, if we want to add a
     * mechanism to ensure that primary sequence is the same on all clients,
     * then we would start to emit different values here.)
     *
     * To give a simple example: suppose we receive, in this order:
     *
     * - [0] `MsgReady(x, 0, {})`
     * - [1] `MsgReady(a, 0, {1})`
     * - [2] `MsgReady(b, 1, {1})`
     *
     * then the client should display, in its primary interface, the sequence
     * of messages as `[x, b, a]`, then (after receiving [2]) highlight `a`,
     * and make available a secondary "message details" interface to indicate
     * that its real parent is `x`. (There is no need to highlight `b` because
     * its true parent is the same as that implied by the primary interface.)
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property mId {string} The message id.
     * @property rIdx {number} The right (negative) index in the existing total
     *      order (i.e. of all previously-emitted MsgReady events) before which
     *      to insert this message in the UI. A sequence of events where these
     *      indexes are all 0, we call "append-only".
     * @property parents {module:mpenc/helper/struct.ImmutableSet} Set of
     *      positive integers, the right-indexes of the parent messages of this
     *      message, relative to the right-index of this message.
     * @memberOf module:mpenc/session
     */
    var MsgReady = struct.createTupleClass("MsgReady", "mId rIdx parents");

    /**
     * Whether the client should highlight this message, to hint the user to
     * look up its real parents (i.e. `log.parents(evt.mId)` not `evt.parents`)
     * in a secondary interface.
     *
     * (This should be ignored for the first message in a sequence, which never
     * requires highlighting, assuming it satisfies `rIdx: 0, parents: {}`.)
     */
    MsgReady.prototype.shouldHighlight = function() {
        return this.parents.size !== 1 || this.parents.values().next().value !== 1;
    };

    /**
     * Create a `MsgReady` from a `SequenceInsert` event on a `MessageLog`.
     *
     * @method
     * @private
     * @param log {module:mpenc/transcript.MessageLog}
     * @param update {module:mpenc/helper/async.SequenceInsert} Update event
     * @returns {module:mpenc/session.MsgReady}
     */
    MsgReady.fromMessageLogUpdate = function(log, update) {
        var rIdx = update.rIdx, mId = update.elem;
        var parents = log.parents(mId).toArray().map(function(pm) {
            return (log.length - rIdx - 1) - log.indexOf(pm);
        });
        _assert(parents.every(function(p) { return p > 0; }));
        return new MsgReady(mId, rIdx, parents);
    };

    Object.freeze(MsgReady.prototype);
    ns.MsgReady = MsgReady;

    /**
     * A packet has not yet been verify-decrypted, even after a grace period.
     *
     * Lazy clients may ignore these events, and non-lazy clients probably want
     * to display these only in a secondary interface.
     *
     * This is probably due to the transport being unreliable (previous messages
     * containing secrets not yet received), but could also be due to a malicious
     * transport, malicious outsiders, or a malicious or buggy sender; and the
     * message has been ignored.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @memberOf module:mpenc/session
     */
    var NotDecrypted = struct.createTupleClass("NotDecrypted", "context sender size");

    ns.NotDecrypted = NotDecrypted;

    /**
     * A message has been decrypted but not accepted, after a grace period.
     * That is, the parent/ancestor messages have not yet all been accepted.
     *
     * Lazy clients may ignore these events, and non-lazy clients probably want
     * to display these only in a secondary interface. There are security
     * implications to showing *too much* of the details of this event (e.g.
     * the contents of the not-yet-accepted message). If this is non-intuitive,
     * see the design paper or developer documentation for details.
     *
     * This probably is due to the transport being unreliable, but could also be
     * due to a malicious transport, or a malicious or buggy sender; and the
     * message has been ignored.
     *
     * The absence of this event does *not* mean the message has been accepted;
     * only the presence of `MsgAccepted` means that.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property uId {string} Verified author.
     * @property pmId {module:mpenc/helper/struct.ImmutableSet} Claimed parent
     *      messages that we timed out waiting for.
     * @memberOf module:mpenc/session
     */
    var NotAccepted = struct.createTupleClass("NotAccepted", "uId pmId");

    Object.freeze(NotAccepted.prototype);
    ns.NotAccepted = NotAccepted;

    /**
     * A message has been accepted but not fully-acked, after a grace period.
     * That is, it may not yet have been seen by all its readers.
     *
     * Clients *must* highlight messages for which this is emitted, to warn the
     * user and communicate this condition. When doing so, clients should take
     * care to not bias the reader towards any particular interpretation on why
     * this event has occured, unless they provide an actual mechanism the user
     * can execute to further diagnose the problem or distinguish the causes.
     *
     * This is probably due to the transport being unreliable, but could also be
     * due to a malicious transport, or a malicious or buggy author (who sent
     * different messages to different readers), or buggy reader(s) (who did not
     * ack the message). It is up to the user to respond appropriately.
     *
     * The absence of this event does *not* mean the message has been fully-acked;
     * only the presence of `MsgFullyAcked` means that.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property mId {string} Message ID.
     * @memberOf module:mpenc/session
     */
    var NotFullyAcked = struct.createTupleClass("NotFullyAcked", "mId");

    Object.freeze(NotFullyAcked.prototype);
    ns.NotFullyAcked = NotFullyAcked;


    /**
     * Things that can be done to/on the cryptographic logical session.
     *
     * One may use {@link module:mpenc/session.checkSessionAction
     * checkSessionAction} to check valid values.
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
     * @see module:mpenc/session.Session#send
     * @see module:mpenc/session.SessionNotice
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
     * A secure group messaging API, for a higher-layer client component that
     * wishes to participate in it. User interfaces should be adapted to *call
     * this interface*, when used with our system.
     *
     * As part of being secure, the session only exists as an contract between
     * its members and *no-one else*. That is, there is no distinction between
     * "we are not part of the session" and "we are the only member".
     *
     * Whilst part of the session, the client receives a sequence of {@link
     * module:mpenc/session.SessionNotice} events from the channel. The order
     * of this sequence may differ slightly between different members. This
     * allows us to guarantee that everyone sees the same true order of events
     * (which cannot be a sequence) that preserves what each author intended.
     * The true order may be queried via other data associated with each event;
     * see the docstring for that event for more details. See also {@link
     * module:mpenc/transcript.MessageLog} for more discussion on ordering.
     *
     * Whilst part of the session, the client can attempt to issue {@link
     * module:mpenc/session~SessionAction} requests. If satisfied then, as
     * stated above, the original context and membership are preserved when
     * readers (or the author) receive the corresponding event.
     *
     * In concrete code terms, `this.curMembers().has(this.owner())` always
     * returns `true`. Moreover, joining or parting another session is viewed
     * as the others being included into or excluded from a local 1-member
     * session; this view is reflected in the data of `SNMembers` events.
     *
     * The instantiated types for `ReceivingExecutor` are:
     *
     * - `{@link module:mpenc/session.Session#send|SendInput}`:
     *   {@link module:mpenc/session~SessionAction}
     * - `{@link module:mpenc/session.Session#onRecv|RecvOutput}`:
     *   {@link module:mpenc/session.SessionNotice}
     *
     * The upper layer may also subscribe to subsets of what `onRecv()`
     * publishes, using {@link module:mpenc/session.Session#onEvent|onEvent}.
     *
     * Implementations *need not* define `execute()` for when the input has a
     * `content` property (i.e. sending a message), but they **must** define it
     * for all other values.
     *
     * @example
     *
     * // For examples on how to obtain a Session, see the mpenc module. We'll
     * // assume you stored that in the 'session' variable, below.
     * //
     * // Variables beginning '?' you need to supply yourself - whatever is
     * // suitable for your UI layer.
     *
     * // Handle events:
     *
     * var log = session.messages();
     * session.onEvent(SNMembers)(function(evt) {
     *   if (evt.isJoin()) {
     *     ?uiMessageView.?renderSelfJoined(evt.include);
     *   } else if (evt.isPart()) {
     *     ?uiMessageView.?renderSelfParted(evt.exclude);
     *   } else {
     *     ?uiMessageView.?renderMembersChanged(evt.include, evt.exclude);
     *   }
     *   ?uiUsersView.?renderMembership(evt.members());
     * });
     * session.onEvent(MsgReady)(function(evt) {
     *   assert(evt.rIdx === 0,
     *     "handling non-append-only sequences is not currently implemented");
     *
     *   var message = log.get(evt.mId);
     *   ?uiMessageView.?renderNewMessage(evt.mId, message.author, message.body.content);
     *
     *   var sessMembers = session.curMembers();
     *   var msgMembers = message.members();
     *   if (!msgMembers.equals(sessMembers)) {
     *     // handle this somehow, see MsgReady docstring for details.
     *   }
     *
     *   if (log.length > 1 && evt.shouldHighlight()) {
     *     var realParents = log.parents(evt.mId);
     *     // handle this somehow, see MsgReady docstring for details.
     *   }
     * });
     * session.onEvent(NotFullyAcked)(function(evt) {
     *   ?uiMessageView.?reRenderMessage(evt.mId, {
     *     notAckedWarning: true,
     *     unackedBy: log.unackby(evt.mId),
     *   });
     * });
     * session.onEvent(MsgFullyAcked)(function(evt) {
     *   ?uiMessageView.?reRenderMessage(evt.mId, {
     *     notAckedWarning: false,
     *   });
     * });
     *
     * // Send messages:
     *
     * var didntFailImmediately = session.send({ content: "Hello, World!" });
     * // MsgReady is published automatically, and handled by your existing recv-hook.
     * // 'didntFailImmediately' might be false if e.g. you were not in the session.
     * // To implement "offline send queues" see mpenc/impl/applied.LocalSendQueue.
     *
     * // Include more members:
     *
     * var promise = session.execute({ include: ?wantToInclude });
     * if (!promise) {
     *   ?uiStatusView.?renderNotice("failed to start invite!");
     *   // return or throw here
     * }
     * ?uiStatusView.?renderNotice(
     *   "inviting: " + wantToInclude + "; please wait... ",
     *   "in the meantime your messages are still encrypted to the old members");
     * promise.then(function() {
     *   ?uiStatusView.?renderNotice("your invite succeeded!");
     *   // SNMembers is published automatically, and handled by your existing recv-hook.
     * }, function() {
     *   ?uiStatusView.?renderNotice("your invite failed! you can try again, though");
     * }).catch(console.log);
     * // Automatic timeouts to reject 'promise' are not yet implemented, but you
     * // could make your own using 'Promise.race()'
     * // Aborting the operation is not yet implemented, but could be in future.
     * // You should *not* need to call any methods on GroupChannel yourself; if you
     * // do then that is our bug that needs to be fixed.
     *
     * // Session join, session part, and member exclude all work similarly.
     * // See doc for SessionAction on what to pass to execute().
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
