/**
 * @fileOverview
 * Graph algorithms.
 */

define([
    "es6-collections",
], function(es6_shim) {
    "use strict";

    /**
     * @exports mpenc/helper/graph
     * Graph algorithms.
     *
     * @description
     * Graph algorithms.
     */
    var ns = {};

    /*
     * Created: 02 Sep 2014-2015 Ximin Luo <xl@mega.co.nz>
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

    /**
     * 1-arg function to get some "associates" of a subject.
     * @callback associates
     * @param subj {}
     * @returns {Array} list of associates
     */

    /**
     * 1-arg function to decide something about a subject.
     * @callback predicate
     * @param subj {}
     * @returns {boolean}
     */

    /**
     * Iterative breadth-first search.
     *
     * @param init {Array} Initial nodes to search from.
     * @param suc {associates} 1-arg function to get successors of a node.
     * @returns {Iterator} Yields unique nodes.
     * @memberOf! module:mpenc/helper/graph
     */
    var bfIterator = function(init, suc) {
        var queue = [].concat(init);
        var seen = new Set();

        return { next: function() {
            if (!queue.length) {
                return { value: undefined, done: true };
            }
            var v = queue.shift();
            seen.add(v);
            var nv = suc(v).filter(function(v, i, a){ return !seen.has(v); });
            queue = queue.concat(nv);
            return { value: v, done: false };
        }};
    };
    ns.bfIterator = bfIterator;

    /**
     * Iterative breadth-first topological search.
     *
     * @param init {Array} Initial nodes to search from.
     * @param suc {associates} 1-arg function to get successors of a node.
     * @param pre {associates} 1-arg function to get predecessors of a node.
     * @param predicate {predicate} Whether to continue searching at a given
     *      node. If this returns false, none of its descendents will be
     *      reached (even if they would have matched). Default: always-True
     * @param boundary {boolean} Whether to return nodes that did satisfy the
     *      predicate (i.e. all nodes traversed), or maximum nodes that did
     *      *not* satisfy the predicate. Default: False.
     * @returns {Iterator} Yields unique nodes in topological order.
     * @memberOf! module:mpenc/helper/graph
     */
    var bfTopoIterator = function(init, suc, pre, predicate, boundary) {
        var queue = [].concat(init);
        var need = new Map();
        predicate = predicate || function() { return true; };
        boundary = !!boundary;

        return { next: function() {
            var v;
            while (true) {
                if (!queue.length) {
                    return { value: undefined, done: true };
                }
                v = queue.shift();
                if (!predicate(v)) {
                    if (boundary) {
                        return { value: v, done: false };
                    }
                } else {
                    var vv = suc(v);
                    for (var i=0; i<vv.length; i++) {
                        var nv = vv[i];
                        if (!need.has(nv)) {
                            need.set(nv, new Set(pre(nv)));
                        }
                        var neednv = need.get(nv);
                        if (!neednv.has(v)) {
                            throw new Error("cycle detecting involving '" + v + "' -> '" + nv + "'");
                        }
                        neednv.delete(v);
                        if (!neednv.size) {
                            queue.push(nv);
                        }
                    };
                    if (!boundary) {
                        return { value: v, done: false };
                    }
                }
            }
        }};
    };
    ns.bfTopoIterator = bfTopoIterator;

    var invertSuccessorMap = function(d) {
        var g = {};
        for (var k in d) {
            if (!(k in g)) {
                g[k] = [];
            }
            var vv = d[k];
            for (var i=0; i<vv.length; i++) {
                var v = vv[i];
                if (v in g) {
                    g[v].push(k);
                } else {
                    g[v] = [k];
                }
            }
        }
        return g;
    };
    ns.invertSuccessorMap = invertSuccessorMap;

    return ns;
});
