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
    "mpenc/helper/struct"
], function(message, assert, struct) {
    "use strict";

    /**
     * @exports mpenc/transcript
     * @private
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
     * @private
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
     * The readers that have not acked the given message.
     *
     * If this is empty, the message has been fully-acked, and this is a
     * certainly-good state. If non-empty, this is a maybe-bad state: the
     * (other) readers *may* have seen the message and even acked it, but
     * we (the local process) have not seen those acks, so we cannot be sure
     * of this. High layers must precisely understand these semantics.
     *
     * We (the local process) consider a message m authored by u to be "acked"
     * by a reader ru, iff we have accepted a message m_a authored by ru
     * where m <= m_a, and there is a chain of messages [m .. m_a] all of
     * which are visible to ru (i.e. authored by them, or by another to them).
     *
     * Note: reaching full-ack locally does not mean that others have reached
     * full-ack themselves. Solving that is the harder "consensus" problem, but
     * it is not necessary for a messaging layer to solve this.
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
     * The send-event is before each accept-event at every reader, and there
     * are no events between these in the causal order, so we effectively treat
     * both as the same event.)
     *
     * Methods taking an mId or uId must raise KeyError if it is absent.
     *
     * @interface
     * @private
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
     * The latest message before mId authored by the given reader of mId, or
     * <code>null</code> if they did not author any such messages.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a reader of mId) to find message for.
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
     * The earliest message after mId authored by the given reader of mId, or
     * <code>null</code> we did not yet see them author such a message.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a reader of mId) to find message for.
     * @returns {?string} Earliest succeeding message id or <code>null</code>.
     */
    Transcript.prototype.suc_ruId;

    Object.freeze(Transcript.prototype);
    ns.Transcript = Transcript;
    // jshint +W030


    /**
     * A log (total order, or linear sequence) of messages for the local user,
     * suitable for directly deriving message elements for the UI. However, it
     * is not guaranteed that every member sees the same total order.
     *
     * Independently of this total order, there is a causal order (or directed
     * acyclic graph), available by querying `parents`. This is the true order
     * of the messages in the session, and it *is* guaranteed that all members
     * see the same causal order. That is, for every message, everyone has the
     * same idea on what the *ancestors* of it are, and may calculate this by
     * recursively calling `parents`. (The *ancestors* of a message is all the
     * messages that had been seen by its author, when they wrote it.)
     *
     * The total order is some topological ordering of the causal order. That
     * is, a message which is earlier than another in the causal order (i.e.
     * reachable via `parents`), is also earlier than it in the total order as
     * well (i.e. has a lower `indexOf`). This prevents most "user surprises"
     * regarding ordering.
     *
     * All of the query methods deal with message IDs (global) and indexes
     * (local to this data structure). To get an actual `Message` object, e.g.
     * to retrieve its contents, first find its message ID, then call `get`.
     *
     * This log only contains `Payload` messages, i.e. those written by human
     * users. Other messages, such as control messages automatically sent by
     * the messaging layer, are hidden from this structure in a way that
     * preserves causality. The documentation for `MessageLog.resolveEarlier`
     * has more details, but this is not part of the public API.
     *
     * @interface
     * @augments module:mpenc/transcript.Messages
     * @memberOf module:mpenc/transcript
     */
    var MessageLog = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * Number of messages in this log.
     *
     * @member
     * @type {number}
     */
    MessageLog.prototype.length;

    /**
     * @method
     * @param index {number} Zero-based index. If negative, this indicates an
     *      offset from the end of the log sequence.
     * @returns {string} ID of the message at the given index.
     */
    MessageLog.prototype.at;

    /**
     * @method
     * @param {string} Message ID.
     * @returns {number} Zero-based index in this log of the given message ID,
     *      or `-1` if the message is not contained in this log.
     */
    MessageLog.prototype.indexOf;

    /**
     * @method
     * @param [begin] {number}
     *      Index at which to begin copying, inclusive. If negative, this
     *      indicates an offset from the end of the log sequence. Default: 0.
     * @param [end] {number}
     *      Index at which to end copying, exclusive. If negative, this
     *      indicates an offset from the end of the log sequence. Default:
     *      current length of the log.
     * @returns {Array} Message IDs contained between the given indexes.
     */
    MessageLog.prototype.slice;

    /**
     * Get the would-be parents of a new message if it were sent now.
     *
     * This is similar to `Transcript.max()`, except that it only returns
     * `Payload` messages.
     *
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of mIds.
     */
    MessageLog.prototype.curParents;

    /**
     * Returns the latest Payload messages before-or-same as the given set of
     * messages. For example, if mIds are the real parents of some message,
     * then this returns the effective Payload parents of that message. For
     * example:
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
     * The output set is guaranteed to be an anti-chain i.e. all causally
     * independent of each other. Note however, that it may not be the same
     * size as the input set, and may even be empty even if the input is not.
     * (However, if the input is empty then the output will be empty.)
     *
     * @private
     * @param transcript {module:mpenc/transcript.Transcript}
     *      Transcript object that contains the messages.
     * @param mIds {module:mpenc/helper/struct.ImmutableSet} Message ids to resolve.
     * @returns {module:mpenc/helper/struct.ImmutableSet} Latest Payload messages.
     * @throws {Error} If not all messages are contained in the transcript.
     */
    MessageLog.resolveEarlier = function(transcript, mIds) {
        if (!mIds.size) {
            return ImmutableSet.EMPTY;
        }
        var it = transcript.iterAncestors(mIds.toArray(),
            null, MessageLog.shouldIgnore.bind(null, transcript), true);
        return new ImmutableSet(struct.iteratorToArray(it));
    };

    /**
     * Whether a given message should be ignored for MsgReady purposes, i.e. if
     * it is not a Payload message.
     *
     * @private
     * @param transcript {module:mpenc/transcript.Transcript}
     *      Transcript object that contains the message.
     * @param mId {string} Message id to check.
     * @returns {boolean} Whether the given message id is a non-Payload message.
     * @throws {Error} If not the message is not contained in the transcript.
     */
    MessageLog.shouldIgnore = function(transcript, mId) {
        return !(transcript.get(mId).body instanceof message.Payload);
    };

    ns.MessageLog = MessageLog;
    // jshint +W030

    return ns;
});
