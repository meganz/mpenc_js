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
     * Wrapper around a "get()"-capable object (e.g. Map) that throws
     * <code>ReferenceError</code> when the result is <code>undefined</code>.
     */
    var safeGet = function(gettable, key) {
        var result = gettable.get(key);
        if (result === undefined) {
            throw new ReferenceError("invalid key: " + key);
        }
        return result;
    };
    ns.safeGet = safeGet;

    /**
     * Apply a function to an ES6 iterator, ignoring its "return value".
     *
     * @param iter {Iterator} Iterator to run through.
     * @param func {function} 1-arg function to apply to each element.
     * @memberOf! module:mpenc/helper/struct
     */
    var iteratorForEach = function(iter, func) {
        // work around https://github.com/WebReflection/es6-collections/issues/22
        if (iter instanceof Array) return iter.forEach(func);
        var done = false;
        while (!done) {
            var result = iter.next();
            done = result.done;
            if (!done) {
                func(result.value);
            } else {
                return result.value;
            }
        }
    };
    ns.iteratorForEach = iteratorForEach;

    /**
     * Populate an array using an ES6 iterator, ignoring its "return value".
     *
     * @param iter {Iterator} Iterator to run through.
     * @returns {Array} Yielded values of the iterator.
     * @memberOf! module:mpenc/helper/struct
     */
    var iteratorToArray = function(iter) {
        var a = [];
        iteratorForEach(iter, function(v) { a.push(v); });
        return a;
    };
    ns.iteratorToArray = iteratorToArray;

    /**
     * An immutable set, intended to match facebook's <a
     * href="https://github.com/facebook/immutable-js/">Immutable JS</a>
     * library. We don't use that, because it is 42kb and we only need Set.</p>
     *
     * <p>Equality in equals() is taken strictly, using <code>===</code>. May
     * be used as a factory method, without <code>new</code>.</p>
     *
     * <p>Does not scale to massive sizes, but should be adequate for
     * representing (e.g.) members of a chat.</p>
     *
     * @class
     * @param {...*} ... Elements of the set
     * @memberOf! module:mpenc/helper/struct
     */
    var ImmutableSet = function(iterable) {
        if (!(this instanceof ImmutableSet)) return new ImmutableSet(iterable);

        var items = new Set(iterable);

        // facebook ImmutableSet provides length
        this.length = items.size;
        this.size = items.size;

        // adhere to the Iterable interface if available
        if (typeof Symbol !== "undefined") {
            // ES6 current standard
            this[Symbol.iterator] = function() {
                return items[Symbol.iterator]();
            };
        } else if ("@@iterator" in items) {
            // at time of writing, Firefox ESR (31) uses an older syntax
            // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...of#Browser_compatibility
            this["@@iterator"] = function() {
                return items["@@iterator"]();
            };
        }

        /**
         * Apply a function to every member. The callback is the same as Set.
         * @param callback {forEachCallback} Function to execute for each element.
         * @param thisObj {} Value to use as <code>this</code> when executing <code>callback</code>.
         */
        this.forEach = function(callback, thisObj) {
            return items.forEach(function(v, v0, a) {
                // prevent external acccess to mutable set
                return callback.call(thisObj, v, v0, this);
            });
        };

        /**
         * Return a Iterator of the elements contained in this set.
         */
        this.values = function() {
            return items.values();
        };

        /**
         * Whether the set contains the given element.
         * @returns {boolean}
         */
        this.has = function(elem) {
            return items.has(elem);
        };
    };

    /**
     * Return a sorted array representation of this set.
     * @returns {Array}
     */
    ImmutableSet.prototype.toArray = function() {
        var a = [];
        this.forEach(function(v) { a.push(v); });
        a.sort();
        return a;
    };

    /**
     * Return a string representation of this set.
     * @returns {string}
     */
    ImmutableSet.prototype.toString = function() {
        return "ImmutableSet(" + this.toArray() + ")";
    };

    /**
     * Return a mutable copy of this set.
     * @returns {Set}
     */
    ImmutableSet.prototype.asMutable = function() {
        return new Set(this);
    };

    /**
     * Return whether this set equals another set.
     * @param {module:mpenc/helper/struct.ImmutableSet} other
     * @returns {boolean}
     */
    ImmutableSet.prototype.equals = function(other) {
        if (!other || other.size !== this.size) {
            return false;
        }
        var eq = true;
        this.forEach(function(v) {
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
    ImmutableSet.prototype.union = function(other) {
        var union = other.asMutable();
        this.forEach(function(v) {
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
    ImmutableSet.prototype.intersect = function(other) {
        var intersection = new Set();
        this.forEach(function(v) {
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
    ImmutableSet.prototype.subtract = function(other) {
        var difference = this.asMutable();
        this.forEach(function(v) {
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
    ImmutableSet.prototype.diff = function(newer) {
        return [newer.subtract(this), this.subtract(newer)];
    };

    /**
     * Apply a difference to an older set.
     *
     * @param older {module:mpenc/helper/struct.ImmutableSet} Older set
     * @param diff {module:mpenc/helper/struct.ImmutableSet[]} 2-tuple of what to (add, remove).
     * @returns {module:mpenc/helper/struct.ImmutableSet} Newer set
     */
    ImmutableSet.prototype.patch = function(diff) {
        if (!diff || diff[0].intersect(diff[1]).size > 0) {
            throw new Error("invalid diff: " + diff);
        }
        return this.union(diff[0]).subtract(diff[1]);
    };

    /**
     * Do a 3-way merge between this parent set and two child sets.
     * @param {module:mpenc/helper/struct.ImmutableSet} first child
     * @param {module:mpenc/helper/struct.ImmutableSet} other child
     * @returns {module:mpenc/helper/struct.ImmutableSet} Result set
     */
    ImmutableSet.prototype.merge = function(child0, child1) {
        return child1.patch(this.diff(child0));
    };

    Object.freeze(ImmutableSet.prototype);
    ns.ImmutableSet = ImmutableSet;

    return ns;
});
