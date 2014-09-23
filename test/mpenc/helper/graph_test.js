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

    var _dict_get = function(d) {
        return function(k) { return d[k]; }
    };

    var _dict_pre = function(g) {
        var gi = ns.invert_dict_graph(g);
        return _dict_get(gi);
    };

    describe("Breadth-first iterative search", function() {
        it("Filter predicate", function() {
            var g = G_with_blocked_path, p = P_with_blocked_path;
            var gen = ns.bf_iter(["1"], function(v) { return g[v].filter(function(nv, i, a) { return p[nv]; }); });
            assert.deepEqual(struct.iter_to_array(gen), ["1", "2", "4"]);
        });
    });

    describe("Breadth-first topological iterative search", function() {
        it("Filter predicate", function() {
            var g = G_with_blocked_path, p = P_with_blocked_path;
            var gen;
            // 4 not in here even though it's reachable from 1, because 3 < 4 and 3 doesn't match
            gen = ns.bf_topo_iter(["1"], _dict_get(g), _dict_pre(g), _dict_get(p));
            assert.deepEqual(struct.iter_to_array(gen), ["1", "2"]);
            // 6 not in here even though it doesn't match, because 3 < 6 and 3 already doesn't match
            gen = ns.bf_topo_iter(["1"], _dict_get(g), _dict_pre(g), _dict_get(p), true);
            assert.deepEqual(struct.iter_to_array(gen), ["3"]);
        });
        it("Raise on cycle", function() {
            var g;

            g = {"1": ["1"]};
            assert.throws(function(){
                struct.iter_to_array(ns.bf_topo_iter(["1"], _dict_get(g), _dict_pre(g)));
            });

            g = {"1": ["2"], "2": ["1"]};
            assert.throws(function(){
                struct.iter_to_array(ns.bf_topo_iter(["1", "2"], _dict_get(g), _dict_pre(g)));
            });

            g = {"1": ["2"], "2": ["3"], "3": ["1"]};
            assert.throws(function(){
                struct.iter_to_array(ns.bf_topo_iter(["1", "2", "3"], _dict_get(g), _dict_pre(g)));
            });
        });
    });
});
