/**
 * @fileOverview
 * Tests for `mpenc/helper/struct` module.
 */

/*
 * Created: 28 Mar 2014 Ximin Luo <xl@mega.co.nz>
 * Contributions: Guy Kloss <gk@mega.co.nz>
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
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "es6-collections",
    "megalogger",
    "chai",
    "sinon/stub",
    "sinon/spy",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, utils, es6_shim, MegaLogger,
            chai, stub, spy, sinon_sandbox, sinon_assert) {
    "use strict";

    var assert = chai.assert;
    var Set = ns.ImmutableSet;
    var diff = ns.Set_diff;
    var patch = ns.Set_patch;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        sandbox.stub(MegaLogger._logRegistry.struct, '_log');
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("MiniSet class", function() {
        describe("constructor, has, and equals", function() {
            it("empty set", function() {
                var a = Set([]);
                assert(a.equals(a));
                assert(a.equals(Set(a)));
                assert(a.equals(Set([])));
                assert(!a.equals(Set([1])));
                assert(!a.equals(null));
                assert(!a.has(null));
            });
            it("singleton with potentially confusing type", function() {
                var a = Set(["3"]);
                assert(a.equals(a));
                assert(a.equals(Set(a)));
                assert(a.equals(Set(["3"])));
                assert(a.has("3"));
                assert(!a.equals(Set([])));
                assert(!a.equals(Set([3])));
                assert(!a.equals(null));
                assert(!a.has(3));
            });
            it("general set", function() {
                var a = Set([1, 2, 3]);
                assert(a.equals(a));
                assert(a.equals(Set(a)));
                assert(a.equals(Set([3, 2, 1])));
                assert(a.equals(Set([2, 3, 1])));
                assert(a.equals(Set([2, 3, 3, 3, 1])));
                assert(a.has(1));
                assert(a.has(2));
                assert(a.has(3));
                assert(!a.equals(Set([2, 1])));
                assert(!a.equals(Set([1, 2, 3, 4])));
                assert(!a.equals(null));
                assert(!a.has("3"));
                assert(!a.has("2"));
            });
        });
        describe("toArray, asMutable", function() {
            it("empty set", function() {
                var a = Set([]);
                var b = a.asMutable();
                b.add(1);
                assert(!a.equals(b));
                assert.sameMembers(a.toArray(), []);
            });
            it("singleton with potentially confusing type", function() {
                var a = Set(["3"]);
                var b = a.asMutable();
                b.add(1);
                assert(!a.equals(b));
                assert.sameMembers(a.toArray(), ["3"]);
                assert.deepEqual(a.toArray(), ["3"]);
                assert.notDeepEqual(a.toArray(), [3]);
            });
            it("general set", function() {
                var a = Set([1, 2, 3]);
                var b = a.asMutable();
                assert(a.equals(b));
                b.add(1);
                assert(a.equals(b));
                b.add(4);
                assert(!a.equals(b));
                var c = a.asMutable();
                assert(a.equals(c));
                c.add(4);
                assert(!a.equals(c));
                assert(Set(c).equals(b));
                assert.sameMembers(a.toArray(), [1, 3, 2]);
            });
        });
        describe("binary operators", function() {
            it("empty set", function() {
               var a = Set([]), b = Set([]);
               assert(a.equals(b));
               assert(a.union(b).equals(b.union(a)));
               assert(a.union(b).equals(a));
               assert(a.union(b).equals(b));
               assert(a.intersect(b).equals(b.intersect(a)));
               assert(a.intersect(b).equals(a));
               assert(a.intersect(b).equals(b));
               assert(a.subtract(b).equals(b.subtract(a)));
               assert(a.subtract(b).equals(a));
               assert(a.subtract(b).equals(b));
            });
            it("general set", function() {
               var a = Set([1, 2, 3]), b = Set([3, 4, 5]);
               assert(!a.equals(b));
               assert(a.union(b).equals(b.union(a)));
               assert(!a.union(b).equals(a));
               assert(!a.union(b).equals(b));
               assert(a.union(b).equals(Set([5, 4, 3, 2, 1])));
               assert(a.intersect(b).equals(b.intersect(a)));
               assert(!a.intersect(b).equals(a));
               assert(!a.intersect(b).equals(b));
               assert(a.intersect(b).equals(Set([3])));
               assert(!a.subtract(b).equals(b.subtract(a)));
               assert(!a.subtract(b).equals(a));
               assert(!a.subtract(b).equals(b));
               assert(!b.subtract(a).equals(a));
               assert(!b.subtract(a).equals(b));
               assert(a.subtract(b).equals(Set([2, 1])));
               assert(b.subtract(a).equals(Set([5, 4])));
            });
            it("calculate diff", function() {
                var a = Set([1, 2, 3]), b = Set([3, 4, 5]);
                var changed_a = a.diff(b);
                var changed_b = b.diff(a);
                assert(changed_a[0].equals(changed_b[1]));
                assert(changed_b[0].equals(changed_a[1]));
                assert.sameMembers(changed_a[0].toArray(), [4, 5]);
                assert.sameMembers(changed_b[0].toArray(), [1, 2]);
            });
            it("patch changes", function() {
                var a = Set([1, 2, 3]), b = Set([3, 4, 5]), c = Set([2, 3, 7]);
                assert.throws(function() { return a.patch([Set([1, 2]), Set([1])]); });
                assert.sameMembers(a.patch([Set([1, 4]), Set([2])]).toArray(), [1, 3, 4]);
                assert.sameMembers(b.patch(a.diff(c)).toArray(), [3, 4, 5, 7]);
                assert.sameMembers(a.merge(b, c).toArray(), [3, 4, 5, 7]);
            });
        });
    });

    describe("TrialBuffer class", function() {
        describe("#trial() method", function() {
            it("empty buffer, tryFunc succeeds", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub();
                var tryFunc = stub().returns(true);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                var result = myTrialBuffer.trial(param);
                sinon_assert.calledOnce(paramIdFunc);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, true);
                assert.deepEqual(myTrialBuffer._buffer, {});
                assert.deepEqual(myTrialBuffer._bufferIDs, []);
            });

            it("param in buffer, tryFunc succeeds", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub();
                var tryFunc = stub().returns(true);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'foo': param};
                myTrialBuffer._bufferIDs = [paramID];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 2);
                assert.deepEqual(tryFunc.getCall(0).args, [true, param]);
                assert.strictEqual(result, true);
                assert.deepEqual(myTrialBuffer._buffer, {});
                assert.deepEqual(myTrialBuffer._bufferIDs, []);
            });

            it("param in buffer, tryFunc succeeds, error on dupe key", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub();
                var tryFunc = stub().returns(true);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'foo': param};
                myTrialBuffer._bufferIDs = [paramID, paramID];
                assert.throws(function() { myTrialBuffer.trial(param); },
                              'Parameter was not removed from buffer.');
            });

            it("other param in buffer, tryFunc succeeds", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub();
                var tryFunc = stub();
                tryFunc.onCall(0).returns(true);
                tryFunc.returns(false); // For every following invocation.
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'bar': {'bar': 'baz'}};
                myTrialBuffer._bufferIDs = ['bar'];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 1);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, true);
                assert.deepEqual(myTrialBuffer._buffer, {'bar': {'bar': 'baz'}});
                assert.deepEqual(myTrialBuffer._bufferIDs, ['bar']);
            });

            it("other param in buffer, tryFunc succeeds, old param works", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub();
                var tryFunc = stub().returns(true);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'bar': {'bar': 'baz'}};
                myTrialBuffer._bufferIDs = ['bar'];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 1);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.deepEqual(tryFunc.getCall(1).args, [false, {'bar': 'baz'}]);
                assert.strictEqual(result, true);
                var log = MegaLogger._logRegistry.struct._log.getCall(0).args;
                assert.deepEqual(log, [0, ['Brian unstashed bar']]);
                assert.deepEqual(myTrialBuffer._buffer, {});
                assert.deepEqual(myTrialBuffer._bufferIDs, []);
            });

            it("empty buffer, tryFunc fails", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub().returns(42);
                var tryFunc = stub().returns(false);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                var result = myTrialBuffer.trial(param);
                sinon_assert.calledOnce(paramIdFunc);
                sinon_assert.calledOnce(maxSizeFunc);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, false);
                var log = MegaLogger._logRegistry.struct._log.getCall(0).args;
                assert.deepEqual(log, [0, ['Brian stashed foo']]);
                assert.deepEqual(myTrialBuffer._buffer, {'foo': param});
                assert.deepEqual(myTrialBuffer._bufferIDs, [paramID]);
            });

            it("other param in buffer, tryFunc fails", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub().returns(42);
                var tryFunc = stub().returns(false);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'bar': {'bar': 'baz'}};
                myTrialBuffer._bufferIDs = ['bar'];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 1);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, false);
                assert.deepEqual(myTrialBuffer._buffer, {'bar': {'bar': 'baz'},
                                                         'foo': param});
                assert.deepEqual(myTrialBuffer._bufferIDs, ['bar', paramID]);
            });

            it("other param in buffer, tryFunc fails, buffer exceeds, no drop", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub().returns(1);
                var tryFunc = stub().returns(false);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc, false);
                myTrialBuffer._buffer = {'bar': {'bar': 'baz'}};
                myTrialBuffer._bufferIDs = ['bar'];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 1);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, false);
                var log = MegaLogger._logRegistry.struct._log.getCall(1).args;
                assert.deepEqual(log, [20, ['Brian is 1 items over expected capacity.']]);
                assert.deepEqual(myTrialBuffer._buffer, {'bar': {'bar': 'baz'},
                                                         'foo': param});
                assert.deepEqual(myTrialBuffer._bufferIDs, ['bar', paramID]);
            });

            it("other param in buffer, tryFunc fails, buffer exceeds, dropping", function() {
                var param = {'foo': 'bar'};
                var paramID = 'foo';
                var maxSizeFunc = stub().returns(1);
                var tryFunc = stub().returns(false);
                var paramIdFunc = stub().returns(paramID);
                var myTrialBuffer = new ns.TrialBuffer('Brian', maxSizeFunc, tryFunc, paramIdFunc);
                myTrialBuffer._buffer = {'bar': {'bar': 'baz'}};
                myTrialBuffer._bufferIDs = ['bar'];
                var result = myTrialBuffer.trial(param);
                assert.strictEqual(paramIdFunc.callCount, 1);
                assert.deepEqual(tryFunc.getCall(0).args, [false, param]);
                assert.strictEqual(result, false);
                var log = MegaLogger._logRegistry.struct._log.getCall(1).args;
                assert.deepEqual(log, [30, ['Brian DROPPED bar at size 1, potential data loss.']]);
                assert.deepEqual(myTrialBuffer._buffer, {'foo': param});
                assert.deepEqual(myTrialBuffer._bufferIDs, [paramID]);
            });
        });
    });
});
