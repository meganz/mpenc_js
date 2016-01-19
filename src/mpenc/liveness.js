/*
 * Created: 29 May 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015-2016 by Mega Limited, Auckland, New Zealand
 *     https://mega.nz/
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
     * @private
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
     * @private
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
     * An entity with a transcript that can be flow-controlled.
     *
     * This is more an 'internal-facing" [interface to] a session - separate from it
     * since the functionality here should only be accessible to FlowControl and not
     * the user. Also the current FlowControl system works under the assumption
     * that there is a single underlying transcript to query, which may not be the
     * case for some Session implementations, e.g. HybridSession.
     *
     * @interface
     * @private
     * @memberOf module:mpenc/liveness
     */
    var Flow = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * The uId of the owner of this process, the authors messages.
     * @method
     */
    Flow.prototype.owner;

    /**
     * The transcript object, for making precise queries about the flow's history.
     * @method
     */
    Flow.prototype.transcript;

    /**
     * The current set of members.
     * @method
     */
    Flow.prototype.curMembers;

    /**
     * The tick at which message was accepted.
     * @method
     */
    Flow.prototype.cTime;

    /**
     * The tick at which message was fully-acked, or null if not yet so.
     * @method
     */
    Flow.prototype.kTime;

    /**
     * Whether we want an active process to reach full-ack for a message.
     * @method
     */
    Flow.prototype.needAckmon;

    /**
     * Whether this flow authored the given message.
     * @param mId {string} Message ID
     * @returns {boolean}
     */
    Flow.prototype.owns = function(mId) {
        return this.owner() === this.transcript().author(mId);
    };

    /**
     * The last message written by the owner of the flow.
     * @returns {?string} Message ID
     */
    Flow.prototype.lastOwnMsg = function() {
        var ownBy = this.transcript().by(this.owner());
        return ownBy.length ? ownBy[ownBy.length - 1] : null;
    };

    /**
     * Send an MessageBody to everyone.
     * @method
     */
    Flow.prototype.sendObj;

    /**
     * Re-send a previously-sent message, possibly by someone else.
     * @method
     */
    Flow.prototype.resend;

    /**
     * Get stats for the current flow.
     * @method
     */
    Flow.prototype.getFlowStats;

    Object.freeze(Flow.prototype);
    ns.Flow = Flow;
    // jshint +W030


    return ns;
});
