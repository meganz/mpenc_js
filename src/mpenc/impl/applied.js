/*
 * Created: 04 Sep 2015 Ximin Luo <xl@mega.co.nz>
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
    "mpenc/session",
    "mpenc/helper/assert",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "es6-collections",
    "megalogger"
], function(
    session,
    assert, async, struct, es6_shim, MegaLogger
) {
    "use strict";

    /**
     * @exports mpenc/impl/applied
     * @description
     * Application-level helper utilities.
     */
    var ns = {};

    var logger = MegaLogger.getLogger("applied", undefined, "mpenc");
    var _assert = assert.assert;
    var identity = function(x) { return x; };

    var MsgReady      = session.MsgReady;
    var MsgFullyAcked = session.MsgFullyAcked;
    var NotAccepted   = session.NotAccepted;
    var NotFullyAcked = session.NotFullyAcked;
    var SNMembers     = session.SNMembers;

    var Observable = async.Observable;
    var ImmutableSet = struct.ImmutableSet;

    /**
     * Emitted when a previously-sent message was resent in a new sub-session,
     * possibly with new parents and/or readers.
     *
     * <p>If <code>old_sId</code> is <code>null</code>, that means
     * <code>old_mId</code> is a virtual message id for a not-yet-sent queued
     * message.</p>
     *
     * @class
     * @property old_sId {?string} Session id of the previous message.
     * @property old_mId {string} Message id of the previous message.
     * @property new_sId {string} Session id of the current resent message.
     * @property new_mId {string} Message id of the current resent message.
     * @property manual {boolean} Whether the resend was manual or automatic.
     * @memberOf module:mpenc/impl/applied
     */
    var MsgResent = struct.createTupleClass("MsgResent", "old_sId old_mId new_sId new_mId manual");
    ns.MsgResent = MsgResent;


    var READERS_WILDCARD = {};

    /**
     * A sending queue that offers manual and automatic resending of messages.
     * This helps to smooth out some behaviours in multi-device and offline
     * scenarios.
     *
     * <p>Note that this is a different concept from ciphertext resending in
     * SessionBase/FlowControl. Resends here may result in duplicate Payload
     * messages in different sub-sessions across different devices; this is not
     * easily solved in a secure fashion, i.e. that does not give users false
     * impressions about the history of the session and security properties of
     * their sent messages. By contrast, ciphertext resending is always safe.
     * </p>
     *
     * <p>In this queue, we have a slightly different concept of message-id.
     * These can be either a (normal) real message id from a transcript, or
     * else a virtual message id specific to this queue, to refer to pending
     * messages not-yet-sent. When we refer to "message id" here, this is
     * usually what we mean, unless otherwise specified.</p>
     *
     * <p>Automatic resending takes place under two circumstances; these are
     * roughly as follows:</p>
     *
     * <ul>
     * <li>When the membership changes, and the message was previously <code>
     * NotFullyAcked</code>, and the logical history and membership of the
     * current session is the same as when the original send was tried.</li>
     * <li>(If activated in the constructor) When we join the session, and the
     * message was sent when we were parted, and (only if we were previously
     * joined) the new logical membership is the same as previously.</li>
     * </ul>
     *
     * <p>All other resends must be performed manually from the UI, by calling
     * <code>send()</code> with extra arguments. "Logical" roughly means human
     * level messages and memberships, i.e. ignoring control messages such as
     * explicit acks, and different devices belonging to the same user.</p>
     *
     * <p>The UI is recommended to implement the following behaviours, but this
     * is not necessary for the operation of this class:</p>
     *
     * <ul>
     * <li>If the return value of <code>send()</code> has a <code>null</code>
     * value for its <code>sId</code> field, it should add a "resend" button
     * to the displayed-message.</li>
     * <li>When NotFullyAcked is emitted by the underlying session, it should
     * check if <code>thisQueue.has(evt.mId)</code>. If so, a "resend" button
     * should be added to the displayed-message for the same mId.</li>
     * <li>When MsgFullyAcked is emitted by the underlying session, it should
     * remove any "resend" button from the relevant displayed-message.</li>
     * <li>When MsgResent is emitted by this object (<code>onResent</code>), it
     * should remove any "resend" buttons on the old displayed-message. The
     * new displayed-message may be marked to indicate that it's related to the
     * old one - e.g. prefixed with "resent of $new_mId", or something.</li>
     * <li>The resend button (on a particular displayd-message) should initiate
     * some user process (that maybe involves re-editing the content) that
     * eventually calls <code>send()</code> with the correct <code>old_sId,
     * old_mId</code> values.</li>
     * </ul>
     *
     * @class
     * @param session {module:mpenc/impl/session.HybridSession} HybridSession
     * @param [resolveLogicalMembers] {function} A 1-arg function to resolve an
     *      ImmutableSet of session members (devices) into another ImmutableSet
     *      of logical human-level members (e.g. jabber bare ids). Defaults to
     *      the identity function.
     * @param [tweakResentContent] {function} A 3-arg function taking (content,
     *      old_sId, old_mId) that returns a maybe-tweaked content for the new
     *      logical message. Defaults to returning the first argument.
     * @param [autoSendOffline] {boolean} Automatically send messages that were
     *      queued whilst offline. Defaults to false.
     * @memberOf module:mpenc/impl/applied
     * @see module:mpenc/impl/applied.MsgResent
     */
    var LocalSendQueue = function(session, resolveLogicalMembers, tweakResentContent, autoSendOffline) {
        if (!(this instanceof LocalSendQueue)) {
            return new LocalSendQueue(session, resolveLogicalMembers, tweakResentContent, autoSendOffline);
        }
        this._sess = session;
        this._resolveLogicalMembers = resolveLogicalMembers || identity;
        this._tweakResentContent = tweakResentContent || identity;
        this._autoSendOffline = autoSendOffline || false;

        // messages that the user wants to send.
        this._toSend = []; // [ { parents, members, content } ]
        // active messages that we sent and are waiting to be fully-acked.
        // there can only be one of these at a time - if we try to resend a
        // message, we (as in this queue) will stop worrying about the version
        // of it that was sent previously. (HybridSession itself will still
        // track if it was fully-acked.)
        this._activeSent = []; // [ { sId, mId } ], see _send() for details
        // filter resend attempts; this allows us to avoid resending a message
        // if it was tried very very recently.
        this._mayResend = []; // [ bool ]
        // dummy message-id counter for messages sent whilst offline
        this._offlineId = 0;

        var cancels = [];
        cancels.push(session.onEvent(SNMembers)(this._onSNMembers.bind(this)));
        cancels.push(session.onEvent(NotFullyAcked)(this._onNotFullyAcked.bind(this)));
        cancels.push(session.onEvent(MsgFullyAcked)(this._onFullyAcked.bind(this)));

        this._cancels = async.combinedCancel(cancels);
        this._resent = new Observable();
    };

    LocalSendQueue.prototype._sessionIsOffline = function() {
        return !this._sess._current;
    };

    // Get the "logical" (i.e. Payload) parents of the current session.
    LocalSendQueue.prototype._getLogicalParents = function() {
        var log = this._sess.messages(); // payload parents
        var parents = log.curParents();

        // if we sent the unique parent, keep going backwards since we're
        // effectively replying to the same set of others' messages.
        var owner = this._sess.owner();
        var mId;
        // jshint -W127
        while (parents.size === 1 && (mId = parents.toArray()[0], log.get(mId).author === owner)) {
            parents = log.parents(mId);
        }
        // jshint +W127

        return parents;
    };

    // Get the "logical" (i.e. human user) members of the current session.
    LocalSendQueue.prototype._getLogicalMembers = function() {
        var members = this._sess._current ? this._sess._current.sess.curMembers() :
                      this._sess._previous ? this._sess._previous.sess.curMembers() :
                      READERS_WILDCARD;
        return this._resolveLogicalMembers(members);
    };

    // Check that the pending message at idx has the same (parents, members).
    LocalSendQueue.prototype._checkMatches = function(idx, parents, members) {
        var toSend = this._toSend[idx];
        return toSend.parents.equals(parents) && (
            toSend.members === READERS_WILDCARD || toSend.members.equals(members));
    };

    // Return the index into _toSend/_activeSent for a given mId, or -1 if not
    // found. If sId is given, check that it matches, throw an error if not.
    LocalSendQueue.prototype._find = function(mId, sId) {
        for (var i = 0; i < this._toSend.length; i++) {
            var sent = this._activeSent[i];
            if (sent.mId !== mId) {
                continue;
            }
            if (sId && sent.sId !== sId) {
                throw new Error("unexpected sId for mId: " + btoa(mId) +
                    "; expected: " + btoa(sId) + "; actual: " + btoa(sent.sId));
            }
            return i;
        }
        return -1;
    };

    // Find earliest index in this._toSend where this and all subsequent items
    // have the same logical (parents, members) as the given values. Returns
    // this._toSend.length if not found.
    LocalSendQueue.prototype._findEarliestContinuous = function(parents, members) {
        for (var idx = this._toSend.length - 1; idx >= 0; idx--) {
            if (!this._checkMatches(idx, parents, members)) {
                break;
            }
        }
        return idx + 1;
    };

    /**
     * @param mId {string}
     *      A (real or virtual) message id; see class docstring for details.
     * @returns {boolean} Whether this queue contains the given message.
     */
    LocalSendQueue.prototype.has = function(mId) {
        return this._find(mId) >= 0;
    };

    /**
     * Manually send or resend a message.
     *
     * When resending, the old message is *removed* from this queue, and any
     * auto-resending policies of this class are applied against the logical
     * history and membership of the new message, not the old one.
     *
     * The parameters and return values have the same meanings as the
     * corresponding fields in {@link module:mpenc/impl/applied.MsgResent}.
     *
     * @param content {string} Content to send.
     * @param [old_sId] {?string} Session id of the previous message.
     * @param [old_mId] {string} Message id of the previous message.
     * @returns {{ mId: string, sId: string }} Session id and message id of the
     *      new message.
     */
    LocalSendQueue.prototype.send = function(content, old_sId, old_mId) {
        old_sId = old_sId || null;
        old_mId = old_mId || null;
        if (old_sId) {
            if (this._sessionIsOffline()) {
                throw new Error("can't resend message when offline");
            }
            var old_idx = this._find(old_mId, old_sId);
            if (old_idx < 0) {
                throw new Error("invalid (old_sId, old_mId); either it was never sent via this queue, " +
                    "or it has been obsoleted by a newer pair: (" + btoa(old_sId) + "," + btoa(old_mId) + ")");
            }
            this._drop(old_idx);
        }
        this._toSend.push({
            parents: this._getLogicalParents(),
            members: this._getLogicalMembers(),
            content: content
        });
        var sent = this._send(content);
        this._activeSent.push(sent);
        // may resend immediatly if not-yet-sent; otherwise this will be set to
        // true by onNotFullyAcked.
        this._mayResend.push(!sent.sId);
        if (old_sId) {
            _assert(sent.sId);
            this._resent.publish(new MsgResent(old_sId, old_mId, sent.sId, sent.mId, true));
        }
        return sent;
    };

    /**
     * Subscribe to messages being resent.
     *
     * @param subscriber {module:mpenc/helper/async~subscriber}
     * @returns canceller {module:mpenc/helper/async~canceller}
     * @see module:mpenc/impl/applied.MsgResent
     */
    LocalSendQueue.prototype.onResent = function(sub) {
        return this._resent.subscribe(sub);
    };

    /**
     * Stop responding to events (e.g. auto-resend) on the underlying session.
     */
    LocalSendQueue.prototype.stop = function() {
        this._cancels();
    };

    LocalSendQueue.prototype._send = function(content) {
        var sess = this._sess;
        var r = sess.send({ content: content });
        if (!r) {
            return {
                sId: null,
                mId: sess.sessionId() + ":offline-dummy:" + (this._offlineId++),
            };
        } else {
            return {
                sId: sess._current.sess.sId(),
                mId: sess.messages().at(-1),
            };
        }
    };

    LocalSendQueue.prototype._drop = function(idx) {
        this._toSend.splice(idx, 1);
        this._activeSent.splice(idx, 1);
        this._mayResend.splice(idx, 1);
    };

    LocalSendQueue.prototype._onFullyAcked = function(evt) {
        var idx = this._find(evt.mId);
        var sId = this._activeSent[idx].sId;
        // assert that no other mId with index < idx has the same sId
        // due to strong ordering, they should already have been dropped
        if (idx > 0) {
            _assert(this._activeSent.slice(0, idx).every(function(v) { return v.sId !== sId; }));
        }
        this._drop(idx);
    };

    LocalSendQueue.prototype._onNotFullyAcked = function(evt) {
        var idx = this._find(evt.mId);
        this._mayResend[idx] = true;
        return this._maybeAutoResend(idx);
    };

    LocalSendQueue.prototype._onSNMembers = function(evt) {
        if (this._autoSendOffline) {
            this._maybeAutoSend();
        }
        var idx = this._mayResend.lastIndexOf(true);
        if (idx >= 0) {
            this._maybeAutoResend(idx);
        }
    };

    // Auto-resend messages from older session if un-acked and same context.
    // idx is the queued message to check against the current (parent, members)
    // If idx >= findEC, then resend the latter and everything after it.
    LocalSendQueue.prototype._maybeAutoResend = function(idx) {
        if (this._sessionIsOffline()) {
            return 0;
        }
        var parents = this._getLogicalParents();
        var members = this._getLogicalMembers();
        if (!this._checkMatches(idx, parents, members)) {
            return 0; // not relevant to this rule
        }
        var earliestResend = this._findEarliestContinuous(parents, members);
        if (earliestResend >= this._toSend.length) {
            return 0; // nothing to resend
        }
        _assert(idx >= earliestResend); // since message ids are not forgeable
        var cur_sId = this._sess._current.sess.sId();
        var sent_sId = this._activeSent.slice(-1)[0].sId;
        if (!cur_sId || cur_sId === sent_sId) {
            return 0; // can't resend / no need to resend yet
        }
        for (var i = earliestResend; i < this._toSend.length; i++) {
            var toSend = this._toSend[i];
            var oldSent = this._activeSent[i];
            var sent = this._send(this._tweakResentContent(toSend.content, oldSent.sId, oldSent.mId));
            _assert(sent.sId); // already checked cur_sId non-null
            this._activeSent[i] = sent;
            this._resent.publish(new MsgResent(oldSent.sId, oldSent.mId, sent.sId, sent.mId, false));
        }
        var count = this._toSend.length - earliestResend;
        logger.info("auto-resent last " + count + " logical messages in new sub-session: " + btoa(cur_sId));
        return count;
    };

    // Auto-send messages queued whilst offline.
    LocalSendQueue.prototype._maybeAutoSend = function() {
        if (this._sessionIsOffline() || this._sess._previous) {
            return 0; // not relevant to this rule
        }
        var parents = this._getLogicalParents();
        var members = this._getLogicalMembers();
        var earliestResend = this._findEarliestContinuous(parents, members);
        if (earliestResend >= this._toSend.length) {
            return 0; // nothing to resend
        }
        var cur_sId = this._sess._current.sess.sId();
        for (var i = earliestResend; i < this._toSend.length; i++) {
            var toSend = this._toSend[i];
            var oldSent = this._activeSent[i];
            _assert(oldSent.sId === null); // not sent before
            _assert(this._mayResend[i]);
            toSend.members = members; // might have been wildcard, take it over with the real value
            var sent = this._send(toSend.content);
            _assert(sent.sId); // already checked cur_sId non-null
            this._activeSent[i] = sent;
            this._resent.publish(new MsgResent(oldSent.sId, oldSent.mId, sent.sId, sent.mId, false));
        }
        var count = this._toSend.length - earliestResend;
        logger.info("auto-resent last " + count + " logical messages in new sub-session: " + btoa(cur_sId));
        return count;
    };

    ns.LocalSendQueue = LocalSendQueue;

    return ns;
});
