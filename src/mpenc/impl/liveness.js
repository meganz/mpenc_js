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
    "mpenc/liveness",
    "mpenc/transcript",
    "mpenc/helper/async",
    "mpenc/helper/struct"
], function(liveness, transcript, async, struct) {
    "use strict";

    /**
     * @exports mpenc/impl/liveness
     * @private
     * @description Liveness properties; implementation.
     */
    var ns = {};

    var Monitor = async.Monitor;
    var Subscribe = async.Subscribe;
    var ImmutableSet = struct.ImmutableSet;

    /**
     * Default ConsistencyMonitor.
     *
     * For each active expectation, we start two processes:
     *
     * <ul>
     * <li>a timeout to execute a warning when full-ack isn't reached</li>
     * <li>a Monitor that repeatedly executes until full-ack is reached</li>
     * </ul>
     *
     * The latter is only started if need_ackmon returns True for the key.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/liveness
     * @implements {module:mpenc/liveness.ConsistencyMonitor}
     * @param owner {string} owner of the local process.
     * @param timer {module:mpenc/helper/async.Timer} Timer for scheduling calls.
     * @param subFullAck {function} 1-arg function, takes a key and returns a
     *      Subscribe function for the full-ack event on that key. Subscribers
     *      expect the key as the input (ItemType), not the full event object.
     * @param fullAckTimeout {function} 1-arg function, (key->int), ticks after
     *      which to fire full_ack_warn if full-ack still isn't reached for
     *      that key.
     * @param fullAckWarn {function} 2-arg function, takes (key, final) to
     *      indicate that the key is not yet fully-acked. final is a bool that
     *      is False on a normal timeout and True when we don't expect a chance
     *      to recover, e.g. when we want to close the session immediately.
     * @param needAckmon {function} -arg function, takes a key and returns a
     *      bool, whether this key needs a ack-monitor. Default: always-False,
     *      in which case the remaining constructor args may be omitted.
     * @param unackby {function} 1-arg function, see ConsistencyState.unackby().
     *      Used by the monitor to check for full-ack status.
     * @param mkAckmonIntervals {function} 1-arg function, takes a key and
     *      returns an iterable of int to be passed to the Monitor() constructor.
     * @param handleUnacked {function} 1-arg function, see FlowControl.handle_unacked.
     * @param handleUnackByOwn {function} 1-arg function, see FlowControl.handle_unackbyown.
     */
    var DefaultConsistencyMonitor = function(owner, timer,
            subFullAck, fullAckTimeout, fullAckWarn,
            needAckmon, unackby, mkAckmonIntervals, handleUnacked, handleUnackByOwn) {
        this._owner  = owner;
        this._timer  = timer;

        this._subFullAck = subFullAck;
        this._fullAckTimeout = fullAckTimeout;
        this._fullAckWarn = fullAckWarn;

        this._needAckmon = needAckmon;
        this._unackby = unackby;
        this._mkAckmonIntervals = mkAckmonIntervals;
        this._handleUnacked = handleUnacked;
        this._handleUnackByOwn = handleUnackByOwn;

        this._ackmon  = new Map();
        this._dummy   = new Monitor(timer, 0, function() { return true; });
    };

    /**
     * @inheritDoc
     */
    DefaultConsistencyMonitor.prototype.active = function() {
        return struct.iteratorToArray(this._ackmon.keys());
    };

    /**
     * @inheritDoc
     */
    DefaultConsistencyMonitor.prototype.expect = function(key) {
        Subscribe.wrap(this._subFullAck(key)).withBackup(
            this._timer.after(this._fullAckTimeout(key)),
            this._fullAckWarn.bind(this, key, false), true)(this._stopAckmon.bind(this));

        this._ackmon.set(key, this._needAckmon(key)
                            ? new Monitor(this._timer, this._mkAckmonIntervals(key), this._checkKey.bind(this, key), "full-ack:" + key)
                            : this._dummy);
    };

    DefaultConsistencyMonitor.prototype._checkKey = function(key) {
        var unackby = this._unackby(key);
        if (unackby.has(this._owner)) {
            this._handleUnackByOwn(key);
        }
        if (unackby.size) {
            return this._handleUnacked(key);
        }
        return true;
    };

    DefaultConsistencyMonitor.prototype._stopAckmon = function(key) {
        struct.safeGet(this._ackmon, key).stop();
        this._ackmon.delete(key);
    };

    /**
     * @inheritDoc
     */
    DefaultConsistencyMonitor.prototype.stop = function() {
        var self = this;
        this._ackmon.forEach(function(mon, key) {
            mon.stop();
            self._fullAckWarn(key, true);
        });
    };

    ns.DefaultConsistencyMonitor = DefaultConsistencyMonitor;

    return ns;
});
