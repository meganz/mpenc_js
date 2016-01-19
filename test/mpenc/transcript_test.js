/**
 * @fileOverview
 * Test of the `mpenc/transcript` and `mpenc/impl/transcript` modules.
 */

/*
 * Created: 11 Feb 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Wellsford, New Zealand
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
    "mpenc/transcript",
    "mpenc/impl/transcript",
    "mpenc/message",
    "mpenc/helper/async",
    "mpenc/helper/graph",
    "mpenc/helper/struct",
    "megalogger",
    "chai",
    "sinon/sandbox",
], function(
    ns, impl, message,
    async, graph, struct, MegaLogger,
    chai, sinon_sandbox
) {
    "use strict";
    // jshint -W064

    var assert = chai.assert;

    var ImmutableSet = struct.ImmutableSet;

    var checkAdd = function(transcript, msg) {
        transcript.add(msg);
        graph.CausalOrder.checkInvariants(transcript);
    };

    var M = message.Message;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        var transcriptLogger = MegaLogger.getLogger("transcript");
        sandbox.stub(transcriptLogger, '_log');
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("BaseTranscript class", function() {
        it('empty object', function() {
            var tr = new impl.BaseTranscript();
            graph.CausalOrder.checkInvariants(tr);
            checkAdd(tr, M(0, 50, [], []));
            assert(tr.unackby(0).size === 0);
            assert(tr.unacked().length === 0);
        });

        it('smoke test, various features', function() {
            var tr = new impl.BaseTranscript();
            graph.CausalOrder.checkInvariants(tr);

            var allUId = new Set([50, 51, 52]);

            checkAdd(tr, M(0, 50, [], [51, 52]));
            checkAdd(tr, M(1, 50, [0], [51, 52]));
            checkAdd(tr, M(2, 51, [1], [50, 52]));
            checkAdd(tr, M(3, 52, [1], [50, 51]));
            checkAdd(tr, M(4, 52, [2, 3], [50, 51]));
            checkAdd(tr, M(5, 50, [3], [51, 52]));

            assert(tr.unackby(0).equals(new Set()));
            assert(tr.unackby(1).equals(new Set()));
            assert(tr.unackby(2).equals(new Set([50])));
            assert(tr.unackby(3).equals(new Set([51])));
            assert(tr.unackby(4).equals(new Set([50, 51])));
            assert(tr.unackby(5).equals(new Set([51, 52])));
            assert.deepEqual(tr.unacked(), [2, 3, 4, 5]);

            checkAdd(tr, M(6, 51, [4], [50, 52]));

            assert(tr.unackby(0).equals(new Set()));
            assert(tr.unackby(1).equals(new Set()));
            assert(tr.unackby(2).equals(new Set([50])));
            assert(tr.unackby(3).equals(new Set()));
            assert(tr.unackby(4).equals(new Set([50])));
            assert(tr.unackby(5).equals(new Set([51, 52])));
            assert(tr.unackby(6).equals(new Set([50, 52])));
            assert.deepEqual(tr.unacked(), [2, 4, 5, 6]);

            // per-author total ordering
            assert.throws(function() { tr.add(M(7, 52, [0], [50, 51])); });
            // freshness consistency
            assert.throws(function() { tr.add(M(7, 52, [0, 6], [50, 51])); });
            // parents in anti-chains (not be traversable from each other)
            assert.throws(function() { tr.add(M(7, 52, [4, 6], [50, 51])); });

            assert(tr.allAuthors().equals(allUId));
        });

        it('test that pre must be an anti-chain', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 51, [0], [50, 52]));
            tr.add(M(2, 52, [1], [50, 51]));
            assert(tr.le(0, 2));
            assert.throws(function() { tr.add(M(3, 52, [0, 2], [50, 51])); });
        });

        it('test that all parents must be visible', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 51, [0], [50, 52]));
            tr.add(M(2, 50, [0], [51]));
            assert.throws(function() { tr.add(M(3, 52, [1, 2], [50, 51])); });
        });

        it('test acks don\'t go through messages not visible to the author', function() {
            // essentially the same graph as graph_test.G_with_blocked_path
            // "blocked" nodes are nodes that weren't sent to 52
            // 52's message 0 should ack 1, 2, 4 but not 3, 5, 6 or 8
            var tr = new impl.BaseTranscript();
            tr.add(M(8, 50, [], [51, 52]));
            tr.add(M(6, 50, [8], [51]));
            tr.add(M(5, 51, [8], [50, 52]));
            tr.add(M(4, 50, [6], [51, 52]));
            tr.add(M(3, 51, [4, 5], [50]));
            tr.add(M(2, 50, [4], [51, 52]));
            tr.add(M(1, 51, [2, 3], [50, 52]));
            assert.deepEqual(tr.unacked(), [8, 5, 4, 3, 2, 1]);
            tr.add(M(0, 52, [1], [50, 51]));
            assert.deepEqual(tr.unacked(), [8, 5, 3, 1, 0]);
            assert(tr.unackby(8).equals(new Set([52])));
            assert(tr.unackby(6).equals(new Set([])));
            assert(tr.unackby(5).equals(new Set([50, 52])));
            assert(tr.unackby(4).equals(new Set([])));
            assert(tr.unackby(3).equals(new Set([50])));
            assert(tr.unackby(2).equals(new Set([])));
            assert(tr.unackby(1).equals(new Set([50])));
            assert(tr.unackby(0).equals(new Set([50, 51])));
        });

        var createHellGraph = function(halfsz) {
            // basically same as graph_test.createHellGraph
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51]));
            tr.add(M(1, 50, [0], [51]));
            tr.add(M(2, 51, [0], [50]));
            for (var i=1; i<halfsz; i++) {
                tr.add(M(2*i+1, 50, [2*i-1, 2*i+0], [51]));
                tr.add(M(2*i+2, 51, [2*i-1, 2*i+0], [50]));
            }
            return tr;
        };

        it('test hell graph efficiency', function() {
            this.timeout(this.timeout() * 15);
            var tr = createHellGraph(256);
            graph.CausalOrder.checkInvariants(tr);
        });

        it('test no stack overflow on large transcripts graphs', function() {
            this.timeout(this.timeout() * 40);
            // pretty much same as the corresponding one in graph_test, except that
            // we also test the fact we don't explicitly need to call merge
            // incrementally, because tr.add() does that already
            var tr = createHellGraph(5000);
            assert(tr.mergeMembers([9999, 10000]).equals(new Set([50, 51])));
        });

        it('pre_ruId calculation', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 51, [0], [50, 52]));
            tr.add(M(2, 52, [0], [50, 51]));
            assert.strictEqual(tr.pre_ruId(1, 52), null);
            assert.strictEqual(tr.pre_ruId(2, 51), null);
            assert.strictEqual(tr.pre_ruId(1, 50), 0);
            assert.strictEqual(tr.pre_ruId(2, 50), 0);
        });

        it('pre_pred calculation', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 51, [0], [50, 52]));
            tr.add(M(2, 52, [0], [50, 51]));
            var uId = function(u) {
                return function(m) { return tr.get(m).author === u; };
            };
            assert.deepEqual(tr.pre_pred(1, uId(52)).toArray(), []);
            assert.deepEqual(tr.pre_pred(2, uId(51)).toArray(), []);
            assert.deepEqual(tr.pre_pred(1, uId(50)).toArray(), [0]);
            assert.deepEqual(tr.pre_pred(2, uId(50)).toArray(), [0]);
        });

        it('suc_ruId calculation', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 51, [0], [50, 52]));
            tr.add(M(2, 52, [0], [50, 51]));
            assert.strictEqual(tr.suc_ruId(1, 52), null);
            assert.strictEqual(tr.suc_ruId(2, 51), null);
            assert.strictEqual(tr.suc_ruId(0, 52), 2);
            assert.strictEqual(tr.suc_ruId(0, 51), 1);
        });

        it('suc_ruId indirect', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 50, [0], [51, 52]));
            tr.add(M(2, 51, [1], [50, 52]));
            tr.add(M(3, 52, [1], [50, 51]));
            assert.strictEqual(tr.suc_ruId(2, 52), null);
            assert.strictEqual(tr.suc_ruId(3, 51), null);
            assert.strictEqual(tr.suc_ruId(0, 52), 3);
            assert.strictEqual(tr.suc_ruId(0, 51), 2);
        });

        it('suc_ruId through blocked', function() {
            var tr = new impl.BaseTranscript();
            tr.add(M(0, 50, [], [51, 52]));
            tr.add(M(1, 52, [0], [50]));
            tr.add(M(2, 50, [1], [51, 52]));
            tr.add(M(3, 51, [2], [50, 52]));
            tr.add(M(4, 52, [2], [50, 51]));
            assert.strictEqual(tr.suc_ruId(3, 52), null);
            assert.strictEqual(tr.suc_ruId(4, 51), null);
            assert.strictEqual(tr.suc_ruId(0, 52), 1);
            assert.strictEqual(tr.suc_ruId(0, 51), null);
            assert.strictEqual(tr.suc_ruId(2, 51), 3);
        });
    });

    describe("DefaultMessageLog class", function() {
        var tr = new impl.BaseTranscript();
        tr.add(M("O", "Alice", [], ["Bob"], new message.Payload("x")));
        tr.add(M("A", "Alice", ["O"], ["Bob"], new message.Payload("x")));
        tr.add(M("C", "Alice", ["A"], ["Bob"], new message.ExplicitAck(false)));
        tr.add(M("B", "Bob", ["A"], ["Alice"], new message.Payload("x")));
        tr.add(M("D", "Bob", ["B", "C"], ["Alice"], new message.ExplicitAck(false)));
        tr.add(M("E", "Bob", ["D"], ["Alice"], new message.Payload("x")));
        var mId_ud = "OABE".split("");
        var mId_ex = ["C", "D"];

        var tr2 = new impl.BaseTranscript();
        tr2.add(M("X", "Alice", [], ["Bob"], new message.Payload("x")));
        tr2.add(M("Y", "Alice", ["X"], ["Bob"], new message.Payload("x")));
        tr2.add(M("Z", "Alice", ["Y"], ["Bob"], new message.ExplicitAck(false)));

        var bindSource = function(messageLog, subscribe, transcript, parents) {
            var sub = messageLog.getSubscriberFor(transcript, parents);
            return subscribe(sub);
        };

        it("Payload filtering", function() {
            // make log and publish transcript messages to it
            var obs = new async.Observable();
            var log = new impl.DefaultMessageLog();
            bindSource(log, obs.subscribe, tr);
            var all = tr.all();
            for (var i = 0; i < all.length; i++) {
                obs.publish(all[i]);
            }
            return log;

            assert.strictEqual(log.length, 4);
            for (var i = 0; i < mId_ud.length; i++) {
                assert(log.indexOf(mId_ud[i]) >= 0);
                assert(log.get(mId_ud[i]) !== null);
                assert(log.parents(mId_ud[i]) !== null);
                assert(log.unackby(mId_ud[i]) !== null);
            }
            for (var i = 0; i < mId_ex.length; i++) {
                assert(log.indexOf(mId_ex[i]) < 0);
                // jshint -W083
                assert.throws(function() { log.get(mId_ex[i]); });
                assert.throws(function() { log.parents(mId_ex[i]); });
                assert.throws(function() { log.unackby(mId_ex[i]); });
                // jshint +W083
            }
            assert.deepEqual(log.parents("E").toArray(), ["B"]);
            assert.deepEqual(log.parents("B").toArray(), ["A"]);
        });

        it("MessageLog updates", function() {
            // make log and watch its updates
            var obs = new async.Observable();
            var log = new impl.DefaultMessageLog();
            bindSource(log, obs.subscribe, tr);
            var seen = [];
            log.onUpdate(function(update) {
                seen.push(update.elem);
            });
            // publish transcript messages to log
            var all = tr.all();
            for (var i = 0; i < all.length; i++) {
                obs.publish(all[i]);
            }
            assert.strictEqual(seen.length, 4);
        });

        it("accumulating multiple transcripts", function() {
            var obs1 = new async.Observable();
            var obs2 = new async.Observable();
            var log = new impl.DefaultMessageLog();

            bindSource(log, obs1.subscribe, tr);
            bindSource(log, obs2.subscribe, tr2);
            var acceptOrder = "OACBXDYEZ".split("");
            for (var i = 0; i < acceptOrder.length; i++) {
                var mId = acceptOrder[i];
                var obs = tr2.has(mId) ? obs2 : obs1;
                obs.publish(mId);
            }

            assert.strictEqual(log.length, 4 + 2);
            assert.deepEqual(log.parents("X").toArray(), []);
            assert.deepEqual(log.parents("O").toArray(), []);
            assert.deepEqual(log.slice(), "OABXYE".split(""));
            assert.deepEqual(log.unacked(), "BXYE".split(""));
        });

        it("accumulating multiple transcripts with parent splicing", function() {
            var obs1 = new async.Observable();
            var obs2 = new async.Observable();
            var log = new impl.DefaultMessageLog();

            var binds = [
                [log, obs1.subscribe, tr],
                [log, obs2.subscribe, tr2, new Map([
                    [new ImmutableSet(["C"]), tr]
                ])]
            ];
            var acceptOrder = "0OACB1XDYEZ".split("");
            for (var i = 0; i < acceptOrder.length; i++) {
                var id = acceptOrder[i];
                if (id in binds) {
                    bindSource.apply(null, binds[id]);
                } else {
                    var obs = tr2.has(id) ? obs2 : obs1;
                    obs.publish(id);
                }
            }

            assert.strictEqual(log.length, 4 + 2);
            assert.deepEqual(log.parents("X").toArray(), ["A"]);
            assert.deepEqual(log.parents("O").toArray(), []);
            assert.deepEqual(log.slice(), "OABXYE".split(""));
            assert.deepEqual(log.unacked(), "BXYE".split(""));
        });
    });

    // jshint +W064
});
