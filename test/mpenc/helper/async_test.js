/**
 * @fileOverview
 * Tests for `mpenc/helper/async` module.
 */

/*
 * Created: 30 Mar 2015 Ximin Luo <xl@mega.co.nz>
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
    "mpenc/helper/async",
    "chai",
], function(ns, chai) {
    "use strict";

    var assert = chai.assert;

    var logs = null;
    var cancel_sub = null;
    var assertLog = function(x) { assert.strictEqual(logs.shift(), x); }

    beforeEach(function() {
        logs = [];
        cancel_sub = ns.SubscriberFailure.subscribeGlobal(function(item) { logs.push(item); });
    });

    afterEach(function() {
        cancel_sub();
        assert.deepEqual(logs, []);
        logs = null;
    });

    describe("Observable", function() {
        var cb_x = function(i) {
            logs.push("called x: " + i);
        };

        var cb_y = function(i) {
            logs.push("called y: " + i);
        };

        describe("reentry mode", function() {
            var fail_y = function(i) {
                logs.push("called y: " + i);
                throw new Error("help y");
            };

            var cb_z = function(obs, cancel_ref, i) {
                cancel_ref[0]();
                obs.subscribe(fail_y);
                logs.push("called z: " + i);
            };

            var cancel_x_ref = [undefined];

            it("cancel later subscriber", function() {
                var prep = function(i) {
                    var obs = new ns.Observable();
                    obs.subscribe(cb_x);
                    obs.subscribe(function(i) { return cb_z(obs, cancel_x_ref, i); });
                    cancel_x_ref[0] = obs.subscribe(cb_x);
                    obs.publish(i);
                    return obs;
                };

                var obs = prep(1);
                assertLog("called x: 1");
                assertLog("called z: 1");
                assert.deepEqual(logs, []);

                obs.publish(2);
                assertLog("called x: 2");
                assertLog("called z: 2");
                assertLog("called y: 2");
                assert(logs.shift() instanceof ns.SubscriberFailure);
                assert.deepEqual(logs, []);
            });

            it("cancel earler subscriber", function() {
                var prep = function(i) {
                    var obs = new ns.Observable();
                    cancel_x_ref[0] = obs.subscribe(cb_x);
                    obs.subscribe(function(i) { return cb_z(obs, cancel_x_ref, i); });
                    obs.subscribe(cb_x);
                    obs.publish(i);
                    return obs;
                };

                var obs = prep(1);
                assertLog("called x: 1");
                assertLog("called z: 1");
                assertLog("called x: 1");
                assert.deepEqual(logs, []);

                obs.publish(2);
                assertLog("called z: 2");
                assertLog("called x: 2");
                assertLog("called y: 2");
                assert(logs.shift() instanceof ns.SubscriberFailure);
                assert.deepEqual(logs, []);
            });
        });

        it("subscribe once", function() {
            var obs = new ns.Observable();
            obs.subscribe(cb_x);
            obs.subscribe(cb_y);
            obs.subscribe.once(cb_x);
            obs.subscribe(cb_y);
            obs.subscribe(cb_x);

            obs.publish(1);
            assertLog("called x: 1");
            assertLog("called y: 1");
            assertLog("called x: 1");
            assertLog("called y: 1");
            assertLog("called x: 1");
            assert.deepEqual(logs, []);

            obs.publish(2);
            assertLog("called x: 2");
            assertLog("called y: 2");
            assertLog("called y: 2");
            assertLog("called x: 2");
            assert.deepEqual(logs, []);
        });

        it("cancel multiple", function() {
            var obs = new ns.Observable();
            var cancels = [];
            cancels.push(obs.subscribe(cb_x));
            cancels.push(obs.subscribe(cb_y));
            cancels.push(obs.subscribe.once(cb_x));
            cancels.push(obs.subscribe(cb_y));
            cancels.push(obs.subscribe(cb_x));

            obs.publish(1);
            assertLog("called x: 1");
            assertLog("called y: 1");
            assertLog("called x: 1");
            assertLog("called y: 1");
            assertLog("called x: 1");
            assert.deepEqual(logs, []);

            var cancelAll = ns.combinedCancel(cancels);
            assert(cancelAll());
            obs.publish(2);
            obs.publish(3);
            assert.deepEqual(logs, []);
            assert(!cancelAll());
            obs.publish(3);
            obs.publish(4);
            assert.deepEqual(logs, []);
        })
    });

});
