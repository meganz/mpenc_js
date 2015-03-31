/*
 * Created: 02 Sep 2014 Ximin Luo <xl@mega.co.nz>
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
    "es6-collections",
    "lru-cache"
], function(struct, es6_shim, LRUCache) {
    "use strict";

    /**
     * @exports mpenc/helper/graph
     * @description
     * Graph algorithms.
     */
    var ns = {};

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

    CausalOrder.checkInvariants = function(target) {
        CausalOrder._checkRelations(target);
        CausalOrder._checkAcyclic(target);
        CausalOrder._checkTransitiveReduction(target);
        CausalOrder._checkAuthorTotalOrder(target);
    };

    // https://stackoverflow.com/a/11935263
    var getRandomSubarray = function(arr, size) {
        if (arr.length <= size) return arr;
        var shuffled = arr.slice(0), i = arr.length, temp, index;
        while (i--) {
            index = Math.floor((i + 1) * Math.random());
            temp = shuffled[index];
            shuffled[index] = shuffled[i];
            shuffled[i] = temp;
        }
        return shuffled.slice(0, size);
    };

    CausalOrder._checkRelations = function(target) {
        getRandomSubarray(target.all(), 128).forEach(function(l) {
            if (!(target.le(l, l) && target.ge(l, l))) {
                throw new Error("not reflexive: le/ge on " + l);
            }
            // only sample large graphs, otherwise too costly
            getRandomSubarray(target.all(), 80).forEach(function(m) {
                var le = target.le(l, m), ge = target.ge(l, m);
                if (!( le || ge )) {
                    return;
                }
                if (le && ge && l !== m) {
                    throw new Error("not anti-symmetric: <=, >= both hold for (" + l + ", " + m + ")");
                }
                // only sample large graphs, otherwise too costly
                getRandomSubarray(target.all(), 32).forEach(function(r) {
                    if (le && target.le(m, r) && !target.le(l, r)) {
                        throw new Error("not transitive: (" + l + " <= " + m + " <= " + r + ") but not (" + l + " <= " + r + ")");
                    }
                    if (ge && target.ge(m, r) && !target.ge(l, r)) {
                        throw new Error("not transitive: (" + l + " >= " + m + " >= " + r + ") but not (" + l + " >= " + r + ")");
                    }
                });
            });
        });
    };

    CausalOrder._checkAcyclic = function(target) {
        // TODO(xl): do this later, lazy atm...
        // Transcript already enforces this via another route - namely by
        // its append-only and "parents-must-already-be-added" semantics
    };

    CausalOrder._checkTransitiveReduction = function(target) {
        var is_related = function(pair) { return target.le(pair[0], pair[1]) || target.le(pair[1], pair[0]); };
        var get_pairs = function(arr) {
            return arr.map(function(v, i, a) {
                var b = a.slice();
                b.splice(i, 1);
                return b.map(function(w) { return [v, w]; });
            }).reduce(function(x, y) { return x.concat(y); }, []);
        };
        target.all().forEach(function(v) {
            var related_pre = get_pairs(target.pre(v).toArray()).filter(is_related);
            if (related_pre.length) {
                throw new Error("predecessors of " + v + " not an anti-chain: (" + related_pre.join("), (") + ")");
            }
            var related_suc = get_pairs(target.suc(v).toArray()).filter(is_related);
            if (related_suc.length) {
                throw new Error("successors of " + v + " not an anti-chain: (" + related_suc.join("), (") + ")");
            }
        });
    };

    CausalOrder._checkAuthorTotalOrder = function(target) {
        var reached = new Set();
        target.allAuthors().forEach(function(a) {
            var vv = target.by(a);
            var notTO = [];
            for (var i=0; i<vv.length-1; i++) {
                if (!target.le(vv[i], vv[i+1])) {
                    notTO.push([vv[i], vv[i+1]]);
                }
            }
            if (notTO.length) {
                throw new Error("Event of author " + a + " are not totally ordered: (" + notTO.join("), (") + ")");
            }
            var invalid = vv.filter(function(v) { return target.author(v) !== a; });
            if (invalid.length) {
                throw new Error("Unexpected messages in by() of " + a + ": " + invalid);
            }
            vv.forEach(function(v) { reached.add(v); });
        });
        reached = new struct.ImmutableSet(reached);
        var all = new struct.ImmutableSet(target.all());
        if (!all.equals(reached)) {
            throw new Error("by(a) for a in allAuthors() did not reach all(): " + all.diff(reached));
        }
    };

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

    /**
     * 3-state merge primitive used by {@link module:mpenc/helper/graph~merge}.
     *
     * <p>Implementations must satisfy &forall; p, a, b: f(p, a, b) === f(p, b, a).</p>
     *
     * @callback merge_3way
     * @param parent {Object} State at parent node.
     * @param child0 {Object} State at node 0.
     * @param child1 {Object} State at node 1.
     * @returns {Object} Merged state at child (that has both 0, 1 as parents).
     */

    /**
     * Merge branched state in a causally-ordered history.
     * @callback merge
     * @param parents {module:mpenc/helper/struct.ImmutableSet|Array} Parent nodes to merge.
     * @returns {Object} State of a potential new node with the given parents.
     */

    /**
     * Create a {module:mpenc/helper/graph~merge} function.
     *
     * @param suc {module:mpenc/helper/utils~associates} Get predecessors of a node.
     * @param suc {module:mpenc/helper/utils~associates} Get successors of a node.
     * @param le {module:mpenc/helper/graph.CausalOrder#le} 2-arg function to test &le; relationship in the history.
     * @param state {function} 1-arg function to get the state at a node.
     * @param empty {function} 0-arg function to create an empty state.
     * @param merge3 {module:mpenc/helper/graph~merge_3way} 3-way merge primitive for the state type.
     * @returns {module:mpenc/helper/graph~merge}
     * @memberOf! module:mpenc/helper/graph
     */
    var createMerger = function(pre, suc, le, state, empty, merge3) {
        // lca2(M, m) := max(anc2(M, m)) # lowest common ancestors between M, m
        // anc2(M, m) := { p | p <= m && (p <= m' for some m' in M) }
        var lca2 = function(init, m) {
            var lca = new struct.ImmutableSet(struct.iteratorToArray(bfTopoIterator(
                init, pre, function(v) {
                    return suc(v).filter(function(nv) { return init.some(function(a) { return le(nv, a); }); });
                }, function(v) { return !le(v, m); }, true
            )));
            if (lca.has(m)) {
                throw new Error("merge target " + m + " is a parent of some of " + init);
            } else {
                var children = lca.intersect(new struct.ImmutableSet(init));
                if (children.size) {
                    throw new Error("merge target " + m + " is a child of some of " + children);
                }
            }
            return lca;
        };
        var makeLRUKey = function(array) {
            var arr = array.slice();
            arr.sort();
            return arr.map(function(a) { return btoa(JSON.stringify(a)); }).join("|");
        };
        var cache = new LRUCache({ max: 256 });
        var merge_recursive; // mutually recursive, needs early declaration
        var merge = function(parents) {
            if (parents.toArray) parents = parents.toArray();
            //return merge_recursive(parents); // uncomment to disable caching
            var key = makeLRUKey(parents);
            if (!cache.has(key)) {
                cache.set(key, merge_recursive(parents));
            }
            return cache.get(key);
        };
        // 3-way merge-recursive
        merge_recursive = function(parents) {
            if (parents.length === 0) {
                return empty();
            } else if (parents.length === 1) {
                return state(parents[0]);
            } else {
                var merged = [parents.pop()];
                var merged_state = state(merged[0]);
                while (parents.length) {
                    var v = parents.pop();
                    var merge_base = lca2(merged, v);
                    merged_state = merge3(merge(merge_base), state(v), merged_state);
                    merged.push(v);
                };
                return merged_state;
            }
        };
        return merge;
    };
    ns.createMerger = createMerger;

    return ns;
});
