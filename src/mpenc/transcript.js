/*
 * Created: 28 Mar 2014 Ximin Luo <xl@mega.co.nz>
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

define([
    "mpenc/message",
    "mpenc/helper/assert",
    "mpenc/helper/async",
    "mpenc/helper/struct"
], function(message, assert, async, struct) {
    "use strict";

    /**
     * @exports mpenc/transcript
     * @description
     * Transcript interfaces.
     */
    var ns = {};

    var _assert = assert.assert;
    var ImmutableSet = struct.ImmutableSet;


    /**
     * A collection of related messages, their ids, and some security state
     *
     * Methods taking a message id must throw an Error if it is absent.
     *
     * @interface
     * @memberOf module:mpenc/transcript
     */
    var Messages = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * Whether the message is in this collection. Does not throw an Error.
     * @method
     * @param mId {string} Message (node) id.
     * @returns {boolean} */
    Messages.prototype.has;

    /**
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/message.Message} Message object for the id. */
    Messages.prototype.get;

    /**
     * The immediately-preceding messages seen by the author of mId.
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of mIds. */
    Messages.prototype.parents;

    /**
     * The recipients that have not acked the given message.
     *
     * If this is empty, the message has been fully-acked, and this is a
     * certainly-good state. If non-empty, this is a maybe-bad state: the
     * (other) recipients *may* have seen the message and even acked it, but
     * we (the local process) have not seen those acks, so we cannot be sure
     * of this. High layers must precisely understand these semantics.
     *
     * We (the local process) consider a message m authored by u to be "acked"
     * by a recipient ru, iff we have accepted a message m_a authored by ru
     * where m <= m_a, and there is a chain of messages [m .. m_a] all of
     * which are visible to ru (i.e. authored by them, or by another to them).
     *
     * Note: reaching full-ack locally does not mean that others have reached
     * full-ack themselves. Solving that is the harder "consensus" problem.
     *
     * @method
     * @param {string} mId
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of uIds. */
    Messages.prototype.unackby;

    /**
     * Messages that are not yet fully-acked.
     * @method
     * @returns {Array.<string>} List of mIds in some topological order. */
    Messages.prototype.unacked;

    Object.freeze(Messages.prototype);
    ns.Messages = Messages;
    // jshint +W030


    /**
     * A causally-ordered transcript of messages.
     *
     * Each node represents the acceptance ("delivery" in distributed systems
     * terminology) of a message by the local process, i.e. made available for
     * consumption by higher layers. This occurs in some topological order of the
     * underlying causal order, so that messages received out-of-order are held
     * back from being accepted until all of their predecessors are accepted.
     *
     * (We do not need a separate event to represent when a message is sent.
     * The send-event is before each accept-event at every recipient, and there
     * are no events between these in the causal order, so we effectively treat
     * both as the same event.)
     *
     * Methods taking an mId or uId must raise KeyError if it is absent.
     *
     * @interface
     * @augments module:mpenc/helper/graph.CausalOrder
     * @augments module:mpenc/transcript.Messages
     * @memberOf module:mpenc/transcript
     */
    var Transcript = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * The latest message before mId authored by the same author, or
     * <code>null</code> if mId is the first message authored by them.
     *
     * @method
     * @param mId {string} Message id.
     * @returns {?string} Latest preceding message id or <code>null</code>.
     */
    Transcript.prototype.pre_uId;

    /**
     * The latest message before mId authored by the given recipient of mId, or
     * <code>null</code> if they did not author any such messages.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a recipient of mId) to find message for.
     * @returns {?string} Latest preceding message id or <code>null</code>.
     * */
    Transcript.prototype.pre_ruId;

    /**
     * The latest messages before the given subject, that satisfy a predicate.
     * This acts as a "filtered" view of the parents, and is the same as
     * max(filter(pred, ancestors(v))).
     *
     * @method
     * @param v {string} The subject node
     * @param pred {module:mpenc/helper/utils~predicate} Predicate to filter for.
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    Transcript.prototype.pre_pred;

    /**
     * The earliest message after mId authored by the given recipient of mId, or
     * <code>null</code> we did not yet see them author such a message.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a recipient of mId) to find message for.
     * @returns {?string} Earliest succeeding message id or <code>null</code>.
     */
    Transcript.prototype.suc_ruId;

    Object.freeze(Transcript.prototype);
    ns.Transcript = Transcript;
    // jshint +W030


    /**
     * When a message is accepted into the transcript, in causal order.
     *
     * @class
     * @property mId {string} The message id.
     * @memberOf module:mpenc/transcript
     */
    var MsgAccepted = struct.createTupleClass("MsgAccepted", "mId");

    Object.freeze(MsgAccepted.prototype);
    ns.MsgAccepted = MsgAccepted;

    /**
     * When a message is acked by all of its intended recipients.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property mId {string} The message id.
     * @memberOf module:mpenc/transcript
     */
    var MsgFullyAcked = struct.createTupleClass("MsgFullyAcked", "mId");

    Object.freeze(MsgFullyAcked.prototype);
    ns.MsgFullyAcked = MsgFullyAcked;

    /**
     * When a message is ready to be consumed by higher layers, such as the UI.
     *
     * These events may be published in a different order from MsgAccepted, but
     * should still be a topological (preserves causality) total order. Events
     * are published in sequence from a single EventContext.
     *
     * Typically, only Payload messages are included here. Implementations may
     * expose the Payload-parents of a message mId from transcript ts as:
     *
     * pl_pmId = MsgReady.resolveEarlier(ts, ts.pre(mId));
     *
     * Note the right index definitions. For example, if three events were
     * published as (x, 0, []), (a, 0, [1]), (b, 1, [1]), the overall resulting
     * order would be [x, b, a], with the real parents of b and a both being x.
     *
     * @class
     * @implements module:mpenc/session.SessionNotice
     * @property mId {string} The message id.
     * @property ridx {number} The right (negative) index in the existing total
     *      order before which to insert this message. An ordering where these
     *      indexes are all 0, we call "append-only".
     * @property parents {module:mpenc/helper/struct.ImmutableSet} Set of
     *      integers, the right-indexes of the parent messages, relative to the
     *      current message. (For example, if a transcript is already in a
     *      linear order, this would be {1} for every message.) If this is the
     *      first message in the sequence, then this must be {}. For subsequent
     *      messages, the UI should distinguish messages where this is not {1}.
     * @memberOf module:mpenc/transcript
     */
    var MsgReady = struct.createTupleClass("MsgReady", "mId rIdx parents");

    /**
     * Returns the latest Payload messages before-or-same as the given set of
     * messages. For example, if mIds are the real parents of some message,
     * then this returns the effective Payload parents of that message, as
     * described in the class docstring.
     *
     * The output set is guaranteed to be an anti-chain i.e. all causally
     * independent of each other. Note however, that it may not be the same
     * size as the input set, and may even be empty even if the input is not.
     * (However, if the input is empty then the output will be empty.)
     *
     * @param transcript {module:mpenc/transcript.Transcript}
     *      Transcript object that contains the messages.
     * @param mIds {module:mpenc/helper/struct.ImmutableSet} Message ids to resolve.
     * @returns {module:mpenc/helper/struct.ImmutableSet} Latest Payload messages.
     * @throws {Error} If not all messages are contained in the transcript.
     */
    MsgReady.resolveEarlier = function(transcript, mIds) {
        var it = transcript.iterAncestors(mIds.toArray(),
            null, MsgReady.shouldIgnore.bind(null, transcript), true);
        return new ImmutableSet(struct.iteratorToArray(it));
    };

    /**
     * Whether a given message should be ignored for MsgReady purposes, i.e. if
     * it is not a Payload message.
     *
     * @param transcript {module:mpenc/transcript.Transcript}
     *      Transcript object that contains the message.
     * @param mId {string} Message id to check.
     * @returns {boolean} Whether the given message id is a non-Payload message.
     * @throws {Error} If not the message is not contained in the transcript.
     */
    MsgReady.shouldIgnore = function(transcript, mId) {
        return !(transcript.get(mId).body instanceof message.Payload);
    };

    Object.freeze(MsgReady.prototype);
    ns.MsgReady = MsgReady;


    /**
     * A log (or total order, or linear sequence) of messages for the user.
     *
     * Only contains Payload messages. We generate "apparent" parents for each
     * message, by collapsing non-Payload parents into the nearest Payload
     * ancestor, preserving transitive reduction. For example:
     *
     * <pre>
     *       B - D - E
     *      /   /
     * O - A - C
     * </pre>
     *
     * O is the root; everything is Payload except C, D. Then, the parents of
     * E are {B}, because even though A < C, it is also the case that A < B.
     *
     * @class
     * @extends module:mpenc/helper/async.ObservableSequence
     * @augments module:mpenc/transcript.Messages
     * @memberOf module:mpenc/transcript
     */
    var MessageLog = function() {
        if (!this.add) {
            throw new Error("add() not implemented");
        }
        async.ObservableSequence.call(this);
    };
    // jshint -W030

    MessageLog.prototype = Object.create(async.ObservableSequence.prototype);

    /**
     * Add a message to the log, at an index defined by the implementation.
     *
     * Subscribers to the ObservableSequence trait of this class are notified.
     *
     * @abstract
     * @method
     * @param transcript {module:mpenc/transcript.Transcript} Transcript object that contains the message.
     * @param mId {string} Identifier of the message to add.
     * @param parents {string} Effective Payload parents of this message.
     */
    MessageLog.prototype.add;

    /**
     * Get the would-be parents of a new message if it were sent now.
     *
     * This is similar to <code>Transcript.max()</code>, except that it only
     * returns Payload messages.
     *
     * @abstract
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of mIds.
     */
    MessageLog.prototype.curParents;

    /**
     * Subscribe to MsgAccepted events and maybe add() them to this log.
     *
     * @method
     * @param source {module:mpenc/helper/async.EventSource} Source of MsgAccepted events.
     * @param transcript {module:mpenc/transcript.Transcript} Transcript object that contains the message.
     * @returns {module:mpenc/helper/async~canceller} Canceller for the subscription.
     */
    MessageLog.prototype.bindSource = function(source, transcript) {
        var self = this;
        var totalOrderCb = function(evt) {
            var mId = evt.mId;
            _assert(transcript.has(mId));
            if (MsgReady.shouldIgnore(transcript, mId)) {
                return;
            }
            self.add(transcript, mId,
                MsgReady.resolveEarlier(transcript, transcript.pre(mId)));
        };
        return source.onEvent(MsgAccepted)(totalOrderCb);
    };

    /**
     * Whenever this log is updated, publish a MsgReady event.
     *
     * @method
     * @param source {module:mpenc/helper/async.EventContext} Target for MsgReady events.
     * @returns {module:mpenc/helper/async~canceller} Canceller for the subscription.
     */
    MessageLog.prototype.bindTarget = function(target) {
        var self = this;
        var msgReadyCb = function(update) {
            var rIdx = update.rIdx, mId = update.elem;
            var parents = self.parents(mId).toArray().map(function(pm) {
                return (self.length - rIdx - 1) - self.indexOf(pm);
            });
            _assert(parents.every(function(p) { return p > 0; }));
            target.publish(new MsgReady(mId, rIdx, parents));
        };
        return this.onUpdate(msgReadyCb);
    };

    Object.freeze(MessageLog.prototype);
    ns.MessageLog = MessageLog;
    // jshint +W030

    return ns;
});
