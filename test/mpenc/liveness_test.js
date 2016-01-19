/**
 * @fileOverview
 * Test of the `mpenc/liveness` module.
 */

/*
 * Created: 01 Jun 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/liveness",
    "mpenc/impl/liveness",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "megalogger",
    "chai",
    "sinon/assert",
    "sinon/stub"
], function(ns, impl, async, struct,
    MegaLogger, chai, sinon_assert, stub
) {
    "use strict";

    var assert = chai.assert;
    var ImmutableSet = struct.ImmutableSet;

    var timer;

    beforeEach(function() {
        timer = new async.Timer();
    });

    afterEach(function() {
        timer.stop();
    });

    describe("DefaultConsistencyMonitor", function() {
        var warned = [];
        var fullAckWarn = function(key, early) { warned.push([key, early]); };
        var unackbyMap = new Map();
        var unackby = unackbyMap.get.bind(unackbyMap);
        var mkAckmonIntervals = stub().returns({ next: stub().returns({ value: 5, done: false }) });
        var handleUnacked = stub().returns(false);
        var handleUnackByOwn = stub();

        var mockSubFullAck = function(obs) {
            return stub().returns(obs.subscribe);
        };

        var createConsistencyMonitor = function(owner, subFullAck, fullAckTimeout, needAckmon) {
            return new impl.DefaultConsistencyMonitor(owner, timer,
                subFullAck, fullAckTimeout, fullAckWarn, needAckmon || stub().returns(false),
                unackby, mkAckmonIntervals, handleUnacked, handleUnackByOwn);
        };

        var assertDone = function(done) {
            assert.strictEqual(warned.length, 0);
            done();
        };

        it("constructor", function() {
            var monitor = createConsistencyMonitor("myself");
            assert.strictEqual(monitor._owner,  "myself");
            assert.strictEqual(monitor.active().length,  0);
        });

        it("fullAck timeout", function(done) {
            var monitor = createConsistencyMonitor("myself", mockSubFullAck(new async.Observable()), stub().returns(5));
            monitor.expect(123);
            timer.after(7, function() {
                assert.deepEqual(warned.shift(), [123, false]);
                assert.strictEqual(warned.length, 0);
                monitor.stop();
                assert.deepEqual(warned.shift(), [123, true]);
                assertDone(done);
            });
        });

        it("fullAck reached", function(done) {
            var obs = new async.Observable();
            var monitor = createConsistencyMonitor("myself", mockSubFullAck(obs), stub().returns(5));
            monitor.expect(1234);
            obs.publish(1234);
            timer.after(7, function() {
                monitor.stop();
                assertDone(done);
            });
        });

        it("ackmon", function(done) {
            var obs = new async.Observable();
            var monitor = createConsistencyMonitor("myself", mockSubFullAck(obs), stub().returns(5), stub().returns(true));
            monitor.expect(5555);
            unackbyMap.set(5555, new ImmutableSet(["myself", "Bob"]));
            timer.after(7, function() {
                assert.deepEqual(warned.shift(), [5555, false]);
                assert.strictEqual(handleUnacked.callCount, 1);
                assert.strictEqual(handleUnackByOwn.callCount, 1);
                unackbyMap.set(5555, new ImmutableSet(["Bob"]));
                timer.after(5, function() {
                    assert.strictEqual(handleUnacked.callCount, 2);
                    assert.strictEqual(handleUnackByOwn.callCount, 1);
                    assert.strictEqual(warned.length, 0);
                    monitor.stop();
                    assert.deepEqual(warned.shift(), [5555, true]);
                    assertDone(done);
                });
            });
        });
    });

});
