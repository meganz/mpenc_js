/**
 * @fileOverview
 * Data structures.
 */

define([
    "es6-collections",
], function(es6_shim) {
    "use strict";

    /**
     * @exports mpenc/helper/struct
     * Data structures.
     *
     * @description
     * Data structures.
     */
    var ns = {};

    /*
     * Created: 28 Mar 2014 Ximin Luo <xl@mega.co.nz>
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
     * 3-arg function to iterate over a Collection
     * @callback forEachCallback
     * @param key {} In the case of Set, this is the same as the value.
     * @param value {}
     * @param collection {}
     */

    /**
     * Populate an array using an ES6 iterator, ignoring its "return value".
     *
     * @param iter {Iterator} Iterator to run through.
     * @returns {Array} Yielded values of the iterator.
     * @memberOf! module:mpenc/helper/struct
     */
    var iteratorToArray = function(iter) {
        var a = [];
        var done = false;
        while (!done) {
            var result = iter.next();
            done = result.done;
            if (!done) {
                a.push(result.value);
            }
        }
        return a;
    };
    ns.iteratorToArray = iteratorToArray;

    /**
     * An immutable set, implemented using sorted arrays. Does not scale to
     * massive sizes, but should be adequate for representing (e.g.) members
     * of a chat.
     *
     * <p>Equality in equals() is taken strictly, using <code>===</code>.</p>
     *
     * <p>Use as a <b>factory function</b> as in <code><del>new</del>
     * ImmutableSet([1, 2, 3])</code>.</p>
     *
     * <p>Otherwise, the API is intended to match facebook's <a
     * href="https://github.com/facebook/immutable-js/">Immutable JS</a>
     * library. We don't use that, because it is 42kb and we only need Set.</p>
     *
     * @param {...*} ... Elements of the set
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     * @memberOf! module:mpenc/helper/struct#
     */
    var ImmutableSet = function(iterable) {

        var items = new Set(iterable);

        /** @lends module:mpenc/helper/struct.ImmutableSet.prototype */
        var self = Object.create(ImmutableSet.prototype);

        // facebook ImmutableSet provides length
        self.length = items.size;
        self.size = items.size;

        /**
         * Return an iterator over the elements of this set.
         * @returns {Array}
         */
        self.asMutable = function() {
            return new Set(items);
        };

        /**
         * Return a sorted array representation of this set.
         * @returns {Array}
         */
        self.toArray = function() {
            var a = [];
            items.forEach(function(v) { a.push(v); });
            a.sort();
            return a;
        };

        /**
         * Apply a function to every member. The callback is the same as Set.
         * @param callback {forEachCallback} Function to execute for each element.
         * @param thisObj {} Value to use as <code>this</code> when executing <code>callback</code>.
         */
        self.forEach = function(callback, thisObj) {
            return items.forEach(function(v, v0, a) {
                // prevent acccess to mutable set
                return callback.call(thisObj, v, v0, self);
            });
        };

        /**
         * Return a string representation of this set.
         * @returns {string}
         */
        self.toString = function() {
            return "ImmutableSet(" + self.toArray() + ")";
        };

        /**
         * Whether the set contains the given element.
         * @returns {boolean}
         */
        self.has = function(elem) {
            return items.has(elem);
        };

        /**
         * Return whether this set equals another set.
         * @param {module:mpenc/helper/struct.ImmutableSet} other
         * @returns {boolean}
         */
        self.equals = function(other) {
            if (!other || other.size !== self.size) {
                return false;
            }
            var eq = true;
            items.forEach(function(v) {
                if (!other.has(v)) {
                    eq = false;
                }
            });
            return eq;
        };

        /**
         * Return the disjunction of this and another set, i.e. elements that
         * are in this <b>or</b> the other set.
         * @param {module:mpenc/helper/struct.ImmutableSet} other
         * @returns {module:mpenc/helper/struct.ImmutableSet}
         */
        self.union = function(other) {
            var union = other.asMutable();
            items.forEach(function(v) {
                union.add(v);
            });
            return ImmutableSet(union);
        };

        /**
         * Return the conjunction of this and another set, i.e. elements that
         * are in this <b>and</b> the other set.
         * @param {module:mpenc/helper/struct.ImmutableSet} other
         * @returns {module:mpenc/helper/struct.ImmutableSet}
         */
        self.intersect = function(other) {
            var intersection = new Set();
            items.forEach(function(v) {
                if (other.has(v)) {
                    intersection.add(v);
                }
            });
            return ImmutableSet(intersection);
        };

        /**
         * Return the difference of this and another set, i.e. elements that
         * are in this <b>and not</b> the other set.
         * @param {module:mpenc/helper/struct.ImmutableSet} other
         * @returns {module:mpenc/helper/struct.ImmutableSet}
         */
        self.subtract = function(other) {
            var difference = self.asMutable();
            items.forEach(function(v) {
                if (other.has(v)) {
                    difference.delete(v);
                }
            });
            return ImmutableSet(difference);
        };

        /**
         * Return what was [added, removed] between this and another set, i.e.
         * same as [other.subtract(this), this.subtract(other)].
         * @param {module:mpenc/helper/struct.ImmutableSet} newer
         * @returns {module:mpenc/helper/struct.ImmutableSet[]}
         */
        self.diff = function(newer) {
            return [newer.subtract(self), self.subtract(newer)];
        };

        /**
         * Apply a difference to an older set.
         *
         * @param older {module:mpenc/helper/struct.ImmutableSet} Older set
         * @param diff {module:mpenc/helper/struct.ImmutableSet[]} 2-tuple of what to (add, remove).
         * @returns {module:mpenc/helper/struct.ImmutableSet} Newer set
         */
        self.patch = function(diff) {
            if (!diff || diff[0].intersect(diff[1]).size > 0) {
                throw new Error("invalid diff: " + diff);
            }
            return self.union(diff[0]).subtract(diff[1]);
        };

        /**
         * Do a 3-way merge between this parent set and two child sets.
         * @param {module:mpenc/helper/struct.ImmutableSet} first child
         * @param {module:mpenc/helper/struct.ImmutableSet} other child
         * @returns {module:mpenc/helper/struct.ImmutableSet} Result set
         */
        self.merge = function(child0, child1) {
            return child1.patch(self.diff(child0));
        };

        return self;
    };
    /** @class
     * @see module:mpenc/helper/struct#ImmutableSet */
    ns.ImmutableSet = ImmutableSet;

    return ns;
});
