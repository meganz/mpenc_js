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
    "mpenc/helper/struct",
    "chai",
], function(ns, struct, chai) {
    "use strict";

    var assert = chai.assert;

    var logs = null;
    var cancel_sub = null;
    var assertLog = function(x) { assert.strictEqual(logs.shift(), x); };

    // we will explicitly generate subscribe failures, so avoid console polluting output
    ns.SubscriberFailure.cancelGlobalLog();

    beforeEach(function() {
        logs = [];
        cancel_sub = ns.SubscriberFailure.subscribeGlobal(function(item) { logs.push(item); });
    });

    afterEach(function() {
        cancel_sub();
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

        it("fail fast for bad args", function() {
            var obs = new ns.Observable();
            assert.throws(function() { obs.subscribe(0); });
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
        });
    });

    describe("events", function() {
        var Evt1 = struct.createTupleClass("x", "y");
        var Evt2 = struct.createTupleClass("x", "y", "z");

        it("fail fast for bad args", function() {
            var events = new ns.EventContext([Evt1]);
            assert.throws(function() { events.subscribe(Evt1, 0); });
            assert.throws(function() { events.publish([]); });
        });

        it("basic events", function() {
            var events = new ns.EventContext([Evt1, Evt2]);

            var cancel_x = events.subscribe(Evt1)(function(evt) {
                logs.push("x got: (" + evt.x + ", " + evt.y + ")");
            });

            var cancel_y = events.subscribe(Evt1, [3])(function(evt) {
                logs.push("y got: (" + evt.x + ", " + evt.y + ")");
            });

            var z = function(evt) {
                throw new Error("fail z");
            };
            var cancel_z = events.subscribe(Evt1, [3, 5])(z);

            //console.log(events.activeChildren(Evt1));
            events.publish(new Evt1(1, 3));
            assertLog("x got: (1, 3)");

            events.publish(new Evt1(3, 4));
            assertLog("y got: (3, 4)");
            assertLog("x got: (3, 4)");

            events.publish(new Evt1(3, 5));
            var p = logs.shift();
            assert(p instanceof ns.SubscriberFailure);
            assert.deepEqual(p.sub, z);
            assert.deepEqual(p.item, new Evt1(3, 5));
            assertLog("y got: (3, 5)");
            assertLog("x got: (3, 5)");

            assert(cancel_x());
            assert(!cancel_x());
            assert(cancel_y());
            assert(!cancel_y());
            assert(cancel_z());
            assert(!cancel_z());

            events.publish(new Evt1(3, 5));
            assert.deepEqual(logs, []);
        });

        it("bubble-capture", function() {
            var events = ns.EventContext([Evt1]);

            events.subscribe(Evt1, [], true)(function(evt) { logs.push("outer called c 1"); });
            events.subscribe(Evt1, [], true)(function(evt) { logs.push("outer called c 2"); });
            events.subscribe(Evt1, [1])(function(evt) { logs.push("inner called"); });
            events.subscribe(Evt1)(function(evt) { logs.push("outer called b 1"); });
            events.subscribe(Evt1)(function(evt) { logs.push("outer called b 2"); });

            events.publish(new Evt1(1, 2));

            // same order as browsers
            assertLog("outer called c 1");
            assertLog("outer called c 2");
            assertLog("inner called");
            assertLog("outer called b 1");
            assertLog("outer called b 2");
            assert.deepEqual(logs, []);
        });

        it("subscriber failed", function() {
            var events = ns.EventContext([Evt1]);
            cancel_sub(); // don't log SubscriberFailures, we have too many

            var cancel_x = events.subscribe(Evt1)(function(evt) {
                logs.push("called x");
                throw new Error("fail x");
            });

            var called_y = 0;
            var cancel_y = events.subscribe(Evt1)(function() {
                called_y += 1;
                if (called_y < 2) {
                    logs.push("called y, 1");
                } else {
                    logs.push("called y, 2");
                    throw new Error("fail y");
                }
            });

            events.publish(new Evt1(1, 2));
            events.publish(new Evt1(1, 2));
            assertLog("called x");
            assertLog("called y, 1");
            assertLog("called x");
            assertLog("called y, 2");
            assert(cancel_y());
            assert.deepEqual(logs, []);
        });

        it("subscriber cancel", function() {
            var events = ns.EventContext([Evt1]);

            var cancel_x = events.subscribe(Evt1)(function(evt) {
                logs.push("called x");
            });

            var cancel_y = events.subscribe(Evt1)(function(evt) {
                cancel_x();
                logs.push("called y, cancelled x");
            });

            events.publish(new Evt1(1, 2));
            assertLog("called x");
            assertLog("called y, cancelled x");

            events.publish(new Evt1(1, 2));
            assertLog("called y, cancelled x");
            assert.deepEqual(logs, []);
        });

        it("subscriber cancel self", function() {
            var events = ns.EventContext([Evt1]);

            var cancel_x = events.subscribe(Evt1)(function(evt) {
                logs.push("called x");
            });

            var cancel_y = events.subscribe(Evt1)(function(evt) {
                logs.push("called y, cancelled y");
                cancel_y();
            });

            events.publish(new Evt1(1, 2));
            assertLog("called x");
            assertLog("called y, cancelled y");

            events.publish(new Evt1(1, 2));
            assertLog("called x");
            assert.deepEqual(logs, []);
        });
    });

    describe("timer", function() {
        describe("defaultMsTimer", function() {
            it("zeroTimeoutOrderAdd", function(done) {
                this.timeout(this.timeout() * 4);
                var timer = new ns.Timer();
                timer.after(1, function() { logs.push("cb2"); });
                timer.after(0, function() {
                    logs.push("cb0");
                    timer.after(0, function() { logs.push("cb1"); });
                });
                // wait a bit longer because browsers do delay clamping
                timer.after(15, function() {
                    assertLog("cb0");
                    assertLog("cb1");
                    assertLog("cb2");
                    assert.deepEqual(logs, []);
                    assert.equal(timer.stop(), 1); // 1 for this callback
                    done();
                }, "check");
            });

            it("oneTimeoutOrder", function(done) {
                this.timeout(this.timeout() * 4);
                var timer = new ns.Timer();
                timer.after(2, function() { logs.push("cb1"); });
                timer.after(1, function() { logs.push("cb0"); });
                timer.after(2, function() { logs.push("cb2"); });
                // wait a bit longer because browsers do delay clamping
                timer.after(10, function() {
                    assertLog("cb0");
                    assertLog("cb1");
                    assertLog("cb2");
                    assert.deepEqual(logs, []);
                    assert.equal(timer.stop(), 1); // 1 for this callback
                    done();
                });
            });

            it("oneTimeoutOrderAdd", function(done) {
                this.timeout(this.timeout() * 4);
                var timer = new ns.Timer();
                timer.after(2, function() { logs.push("cb1"); });
                timer.after(1, function() {
                    logs.push("cb0");
                    timer.after(1, function() { logs.push("cb2"); });
                });
                // wait a bit longer because browsers do delay clamping
                timer.after(15, function() {
                    assertLog("cb0");
                    assertLog("cb1");
                    assertLog("cb2");
                    assert.deepEqual(logs, []);
                    assert.equal(timer.stop(), 1); // 1 for this callback
                    done();
                });
            });
        });

        describe("subscribe timeout", function() {
            var cb_x = function() {
                logs.push("called x");
            };
            var fail_x = function() {
                logs.push("timeout x");
            };

            it("default, no allowFireLater", function(done) {
                this.timeout(this.timeout() * 4);
                var timer = new ns.Timer();
                var obs = new ns.Observable();
                var cancel_x = obs.subscribe.withBackup(timer.after(1), fail_x)(cb_x);
                timer.after(20, function() {
                    assertLog("timeout x");
                    assert.deepEqual(logs, []);
                    obs.publish(1);
                    assert(!cancel_x());
                    assert.deepEqual(logs, []);
                    assert.equal(timer.stop(), 1); // 1 for this callback
                    done();
                });
            });

            it("allowFireLater", function(done) {
                this.timeout(this.timeout() * 4);
                var timer = new ns.Timer();
                var obs = new ns.Observable();
                var cancel_x = obs.subscribe.withBackup(timer.after(1), fail_x, true)(cb_x);
                timer.after(5, function() {
                    obs.publish(1);
                });
                timer.after(20, function() {
                    assertLog("timeout x");
                    assertLog("called x");
                    assert.deepEqual(logs, []);
                    assert(cancel_x());
                    assert.deepEqual(logs, []);
                    assert.equal(timer.stop(), 1); // 1 for this callback
                    done();
                });
            });
        });
    });

    describe("Monitor", function() {
        var timer = new ns.Timer();
        var after = timer.after.bind(timer);

        it("basic usage", function(done) {
            this.timeout(this.timeout() * 4);
            var called = 0;
            var times = 3;
            var act = function() {
                logs.push("called act-basic");
                called += 1;
                if (called >= times) {
                    return true;
                }
            };
            var mon = new ns.Monitor(timer, 1, act);
            assert(mon.state() === "RUNNING");
            mon.pause();
            assert.throws(mon.pause.bind(mon));
            assert(mon.state() === "PAUSED");
            mon.resume();
            assert.throws(mon.resume.bind(mon));
            after(50, function() {
                assert.equal(called, 3);
                assertLog("called act-basic");
                assertLog("called act-basic");
                assertLog("called act-basic");
                assert(mon.state() === "STOPPED");
                mon.stop();
                assert(mon.state() === "STOPPED");
                assert.throws(mon.pause.bind(mon));
                assert.throws(mon.resume.bind(mon));
                assert.deepEqual(logs, []);
                done();
            });
        });

        it("fail SubscriberFailure", function(done) {
            this.timeout(this.timeout() * 4);
            var called = 0;
            var times = 1;
            var act = function() {
                logs.push("called act-sf");
                called += 1;
                if (called >= times) {
                    throw new Error("fail action");
                }
            };
            var mon = new ns.Monitor(timer, 1, act);
            after(20, function() {
                assert.equal(called, 1);
                assertLog("called act-sf");
                assert(logs.shift() instanceof ns.SubscriberFailure);
                assert.deepEqual(logs, []);
                done();
            });
        });

        it("finite seq", function(done) {
            this.timeout(this.timeout() * 4);
            var act = function() {
                logs.push("called act-fs");
            };
            var mon = new ns.Monitor(timer, [1, 1, 1, 1], act);
            after(2, function() { logs.push("called middle"); });
            assert(mon.state() === "RUNNING");
            after(50, function() {
                assertLog("called act-fs");
                assertLog("called middle"); // not sure if ordering is part of JS spec
                // but this works on phantomJS/firefox/chrome. if it fails elsewhere, we'll need to be less strict
                assertLog("called act-fs");
                assertLog("called act-fs");
                assertLog("called act-fs");
                assert(mon.state() === "STOPPED");
                assert.deepEqual(logs, []);
                done();
            });
        });

        it("reset", function(done) {
            this.timeout(this.timeout() * 4);
            var act = function() {
                logs.push("called act-reset");
            };
            var mon = new ns.Monitor(timer, [1, 1], act);
            assert(mon.state() === "RUNNING");
            after(30, function() {
                assertLog("called act-reset");
                assertLog("called act-reset");
                assert(mon.state() === "STOPPED");
                assert.deepEqual(logs, []);
                mon.reset([1, 1, 1]);
                after(40, function() {
                    assertLog("called act-reset");
                    assertLog("called act-reset");
                    assertLog("called act-reset");
                    assert(mon.state() === "STOPPED");
                    assert.deepEqual(logs, []);
                    done();
                });
            });
        });
    });

    // polyfill for PhantomJS
    if (!Function.prototype.bind) {
      Function.prototype.bind = function(oThis) { // jshint ignore:line
        if (typeof this !== 'function') {
          // closest thing possible to the ECMAScript 5
          // internal IsCallable function
          throw new TypeError('Function.prototype.bind - what is trying to be bound is not callable');
        }

        var aArgs   = Array.prototype.slice.call(arguments, 1),
            fToBind = this,
            fNOP    = function() {},
            fBound  = function() {
              return fToBind.apply(this instanceof fNOP
                     ? this
                     : oThis,
                     aArgs.concat(Array.prototype.slice.call(arguments)));
            };

        fNOP.prototype = this.prototype;
        fBound.prototype = new fNOP(); // jshint ignore:line

        return fBound;
      };
    }

});
