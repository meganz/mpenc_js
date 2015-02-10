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

    /**
     * A causal order is a partial order, where each element is an event
     * associated with an author/agent, an actor-observer who initiates the
     * event based on (i.e. "caused by", "greater-than") already-observed
     * parent events.
     *
     * The order must also be a transitive reduction. That is, for all m, there
     * must exist no elements between m and any element in pre(m) or suc(m).
     *
     * Methods taking a vertex or author must throw an Error if it is absent.
     *
     * @interface
     * @memberOf module:mpenc/helper/graph
     */
    var CausalOrder = function() {
        throw new Error("cannot instantiate an interface");
    };

    /**
     * Number of elements.
     * @member {number}
     */
    CausalOrder.prototype.length;

    /** All the ids as an array.
     * @method
     * @returns {Array} */
    CausalOrder.prototype.all;

    /** Whether a given item is in this graph.
     * @method
     * @returns {boolean} */
    CausalOrder.prototype.has;

    /** The minimal / first / earliest nodes.
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    CausalOrder.prototype.min;

    /** The maximal / last / latest nodes.
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    CausalOrder.prototype.max;

    /** The direct predecessors of v.
     * @method
     * @param v {string}
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    CausalOrder.prototype.pre;

    /** The direct successors of v.
     * @method
     * @param v {string}
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    CausalOrder.prototype.suc;

    /** True if v0 &le; v1, i.e. v0 = pre<sup>n</sup>(v1) for some n &ge; 0.
     *
     * <p>This is a poset, so ¬(v0 &le; v1) does not imply (v1 &le; v0).</p>
     * @method
     * @param v0 {string}
     * @param v1 {string}
     * @returns {boolean}  */
    CausalOrder.prototype.le;

    /** True if v0 &ge; v1, i.e. v0 = suc<sup>n</sup>(v1) for some n &ge; 0.
     *
     * <p>This is a poset, so ¬(v0 &ge; v1) does not imply (v1 &ge; v0).</p>
     * @method
     * @param v0 {string}
     * @param v1 {string}
     * @returns {boolean}  */
    CausalOrder.prototype.ge;

    /**
     * The latest messages before the given subject, that satisfy a predicate.
     * This acts as a "filtered" view of the parents, and is the same as
     * max(filter(pred, ancestors(v))).
     *
     * @method
     * @param v {string} The subject node
     * @param pred {module:mpenc/helper/utils~predicate} Predicate to filter for.
     * @returns {module:mpenc/helper/struct.ImmutableSet} */
    CausalOrder.prototype.pre_pred;

    /** All authors ever to have participated in this session.
     * @method
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of uIds. */
    CausalOrder.prototype.allAuthors;

    /** The author of the given node/event.
     * @method
     * @param v {string} Node/event id.
     * @returns {string} Author id. */
    CausalOrder.prototype.author;

    /** All events by the given author, totally-ordered.
     * @method
     * @param {string} Author id.
     * @returns {string[]} List of node/event ids. */
    CausalOrder.prototype.by;

    Object.freeze(CausalOrder.prototype);
    ns.CausalOrder = CausalOrder;


    /**
     * Iterative breadth-first search.
     *
     * @param init {Array} Initial nodes to search from.
     * @param suc {module:mpenc/helper/utils~associates} Get successors of a node.
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
     * @param suc {module:mpenc/helper/utils~associates} Get successors of a node.
     * @param pre {module:mpenc/helper/utils~associates} Get predecessors of a node.
     * @param predicate {module:mpenc/helper/utils~predicate} Whether to
     *      continue searching at a given node. If this returns false, none of
     *      its descendents will be reached (even if they would have matched).
     *      Default: always-True
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
