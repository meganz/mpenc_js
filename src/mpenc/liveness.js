/*
 * Created: 29 May 2015 Ximin Luo <xl@mega.co.nz>
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
    "mpenc/helper/struct"
], function(struct) {
    "use strict";

    /**
     * @exports mpenc/liveness
     * @description Liveness properties - reliability, recovery, consistency, freshness, etc.
     */
    var ns = {};

    /**
     * Monitor for consistency expectations to be met.
     *
     * Typically, there should be a timeout-based warning emitted to clients if
     * the expectation is not met. Optionally, there could be a secondary
     * process (such as async.Monitor) that actively tries to meet the
     * expectation.
     *
     * @interface
     * @memberOf module:mpenc/liveness
     */
    var ConsistencyMonitor = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * Keys that we are expecting a future full-ack for.
     * @method
     * @returns {Array} */
    ConsistencyMonitor.prototype.active;

    /**
     * Set an expectation for a key to become fully-acked.
     * @method
     * @param key {object} Key
     */
    ConsistencyMonitor.prototype.expect;

    /**
     * Stop all running monitors.
     * @method
     */
    ConsistencyMonitor.prototype.stop;

    Object.freeze(ConsistencyMonitor.prototype);
    ns.ConsistencyMonitor = ConsistencyMonitor;
    // jshint +W030


    /**
     * A message has been decrypted but not accepted, after a grace period.
     * That is, the parent/ancestor messages have not yet all been accepted.
     *
     * This probably is due to the transport being unreliable, but could also be
     * due to a malicious transport, or a malicious or buggy sender; and the
     * message has been ignored.
     *
     * The absence of this event does *not* mean the message has been accepted;
     * to check this, either wait for MsgAccepted (its absence means the message
     * has *not* been accepted) or check Transcript for the message.
     *
     * @property uId {string} Verified author.
     * @property pmId {module:mpenc/helper/struct.ImmutableSet} Claimed parent
     *      messages that we timed out waiting for.
     */
    var NotAccepted = struct.createTupleClass("uId", "pmId");

    Object.freeze(NotAccepted.prototype);
    ns.NotAccepted = NotAccepted;


    /**
     * A message has been accepted but not fully-acked, after a grace period.
     * That is, it may not yet have been accepted by all its recipients.
     *
     * This is probably due to the transport being unreliable, but could also be
     * due to a malicious transport, or a malicious or buggy sender (who sent
     * different messages to different recipients), or buggy recipient(s) (who
     * did not ack the message). It is up to the user to respond appropriately.
     *
     * The absence of this event does *not* mean the message has been fully-acked;
     * to check this, either wait for MsgFullyAcked (its absence means the message
     * has *not* been fully-acked) or check Transcript.unacked() for the message.
     */
    var NotFullyAcked = struct.createTupleClass("mId");

    Object.freeze(NotFullyAcked.prototype);
    ns.NotFullyAcked = NotFullyAcked;


    return ns;
});
