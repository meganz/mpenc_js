/**
 * @fileOverview
 * Tests for `mpenc/helper/graph` module.
 */

/*
 * Created: 02 Sep 2014 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2014 by Mega Limited, Wellsford, New Zealand
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
    "mpenc/helper/graph",
    "mpenc/helper/struct",
    "chai",
], function(ns, struct, chai) {
    "use strict";

    var assert = chai.assert;
    var Set = struct.ImmutableSet;

    // JS objects have *string* properties, using numbers results in unpredictable behaviour
    var G_with_blocked_path = {
        "1": ["2", "3"],
        "2": ["4"],
        "3": ["4", "5"],
        "4": ["6"],
        "5": [],
        "6": [],
    };

    var P_with_blocked_path = {
        "1": true,
        "2": true,
        "3": false,
        "4": true,
        "5": true,
        "6": false,
    };

    var _objGetter = function(d) {
        return function(k) { return d[k]; }
    };

    var _preGetter = function(g) {
        var gi = ns.invertSuccessorMap(g);
        return _objGetter(gi);
    };

    describe("Breadth-first iterative search", function() {
        it("Filter predicate", function() {
            var g = G_with_blocked_path, p = P_with_blocked_path;
            var gen = ns.bfIterator(["1"], function(v) { return g[v].filter(function(nv, i, a) { return p[nv]; }); });
            assert.deepEqual(struct.iteratorToArray(gen), ["1", "2", "4"]);
        });
    });

    describe("Breadth-first topological iterative search", function() {
        it("Filter predicate", function() {
            var g = G_with_blocked_path, p = P_with_blocked_path;
            var gen;
            // 4 not in here even though it's reachable from 1, because 3 < 4 and 3 doesn't match
            gen = ns.bfTopoIterator(["1"], _objGetter(g), _preGetter(g), _objGetter(p));
            assert.deepEqual(struct.iteratorToArray(gen), ["1", "2"]);
            // 6 not in here even though it doesn't match, because 3 < 6 and 3 already doesn't match
            gen = ns.bfTopoIterator(["1"], _objGetter(g), _preGetter(g), _objGetter(p), true);
            assert.deepEqual(struct.iteratorToArray(gen), ["3"]);
        });
        it("Raise on cycle", function() {
            var g;

            g = {"1": ["1"]};
            assert.throws(function(){
                struct.iteratorToArray(ns.bfTopoIterator(["1"], _objGetter(g), _preGetter(g)));
            });

            g = {"1": ["2"], "2": ["1"]};
            assert.throws(function(){
                struct.iteratorToArray(ns.bfTopoIterator(["1", "2"], _objGetter(g), _preGetter(g)));
            });

            g = {"1": ["2"], "2": ["3"], "3": ["1"]};
            assert.throws(function(){
                struct.iteratorToArray(ns.bfTopoIterator(["1", "2", "3"], _objGetter(g), _preGetter(g)));
            });
        });
    });

    describe("Merging state in history", function() {
        var assertMergeSymmetry = function(merger, parents, expected) {
            // from http://stackoverflow.com/a/22063440
            var permutations = parents.reduce(function permute(res, item, key, arr) {
                return res.concat(arr.length <= 1? item:
                    arr.slice(0, key).concat(arr.slice(key + 1)).reduce(permute, []).map(
                        function(perm) { return [item].concat(perm); }));
            }, []);
            var factorial = 1;
            for (var i=2; i<=parents.length; i++) factorial *= i;
            assert(permutations.length === factorial);
            permutations.forEach(function(par) {
                assert(par.length === parents.length);
                assert(merger(par).equals(expected));
            });
        };

        it("single root set subtraction", function() {
            // naive merge implementations would return "abcdx"
            var g = {
                "0": [],
                "1": ["0"],
                "2": ["0"],
                "3": ["2"],
                "4": ["2"]
            };
            var s = {
                "0": new Set("a".split("")),
                "1": new Set("ax".split("")),
                "2": new Set("abc".split("")),
                "3": new Set("abcd".split("")),
                "4": new Set("ab".split("")),
            }
            var lt = ["01", "02", "03", "04", "23", "24"];
            var le = function(a, b) { return a === b || lt.indexOf(""+a+""+b) >= 0; };
            var merger = ns.createMerger(_objGetter(g), _preGetter(g), le,
                function(k) { return s[k]; }, Set, function(p, a, b) { return p.merge(a, b); });

            assertMergeSymmetry(merger, ["1", "3", "4"], new Set("abdx".split("")));
        });
        it("multiple roots set subtraction", function() {
            // naive merge implementations would return "bcdx"
            var g = {
                "1": [],
                "2": [],
                "3": ["2"],
                "4": ["2"]
            };
            var s = {
                "1": new Set("x".split("")),
                "2": new Set("bc".split("")),
                "3": new Set("bcd".split("")),
                "4": new Set("b".split("")),
            }
            var lt = ["23", "24"];
            var le = function(a, b) { return a === b || lt.indexOf(""+a+""+b) >= 0; };
            var merger = ns.createMerger(_objGetter(g), _preGetter(g), le,
                function(k) { return s[k]; }, Set, function(p, a, b) { return p.merge(a, b); });

            assertMergeSymmetry(merger, ["1", "3", "4"], new Set("bdx".split("")));
        });

        var createHellGraph = function(halfsz) {
            var g = {};
            g["0"] = [];
            g["1"] = ["0"];
            g["2"] = ["0"];
            for (var i=1; i<halfsz; i++) {
                g[""+(2*i+1)] = [""+(2*i-1), ""+(2*i+0)];
                g[""+(2*i+2)] = [""+(2*i-1), ""+(2*i+0)];
            }
            return g;
        };
        it("hell graph completes in a sane amount of time", function() {
            this.timeout(this.timeout() * 5);
            var g = createHellGraph(50000);
            var le = function(a, b) { a = parseInt(a); b = parseInt(b); return (b & 1)? a <= b: (a == b || a <= b-2); };
            var dummy_state = function(k) { return new Set(); };

            var merger = ns.createMerger(_objGetter(g), _preGetter(g), le,
                dummy_state, Set, function(p, a, b) { return p.merge(a, b); });

            // unfortunately this stack-overflows. iterative algorithm is a *lot* more complex...
            assert.throws(function() { merger(["99999", "100000"]); });
            // for the Transcript case, caching saves us - we run merge() on all messages, so
            // parents are usually already cached => few recursive calls. so this should not
            // be a problem even for transcripts with 100k+ messages.
            for (var i=2000; i<100001; i+=2000) {
                assertMergeSymmetry(merger, [""+(i-1), ""+i], new Set());
            }
        });
    });
});
