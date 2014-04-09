/**
 * @fileOverview
 * Data structures.
 */

define([], function() {
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
     * An immutable set, implemented using sorted arrays. Does not scale to
     * massive sizes, but should be adequate for representing (e.g.) members
     * of a chat.
     *
     * <p>Equality is taken strictly, using <code>===</code>.</p>
     *
     * <p>Use as a <b>factory function</b> as in <code><del>new</del>
     * MiniSet(1, 2, 3)</code>.</p>
     *
     * @param {...*} ... Elements of the set
     * @returns {module:mpenc/helper/struct.MiniSet}
     * @memberOf! module:mpenc/helper/struct#
     */
    var MiniSet = function() {

        var items = Array.prototype.slice.call(arguments, 0);
        items.sort();
        items = items.filter(function (v, i, a) {
            // deduplicate already-sorted array
            return (i == 0 || a[i-1] !== v);
        });

        // http://stackoverflow.com/a/16436975
        var arraysEqual = function(a, b) {
            if (a === b) { return true; }
            if (a == null || b == null) { return false; }
            if (a.length != b.length) { return false; }

            for (var i = 0; i < a.length; ++i) {
                if (a[i] !== b[i]) { return false; }
            }
            return true;
        };

        /** @lends module:mpenc/helper/struct.MiniSet.prototype */
        var self = Object.create(MiniSet.prototype);

        /**
         * Return a sorted-array representation of this set.
         * @returns {Array}
         */
        self.toArray = function() {
            return [].concat(items);
        };

        /**
         * Return a string representation of this set.
         * @returns {string}
         */
        self.toString = function() {
            return "MiniSet(" + items.join(", ") + ")";
        };

        /**
         * Whether the set contains the given element.
         * @returns {boolean}
         */
        self.contains = function(elem) {
            // just do linear search, the set is small
            return items.indexOf(elem) >= 0;
        };

        /**
         * Return whether this set equals another set.
         * @param {module:mpenc/helper/struct.MiniSet} other
         * @returns {boolean}
         */
        self.equals = function(other) {
            if (!other || !other.toArray) { return false; }
            return arraysEqual(items, other.toArray());
        };

        /**
         * Return the disjunction of this and another set, i.e. elements that
         * are in this <b>or</b> the other set.
         * @param {module:mpenc/helper/struct.MiniSet} other
         * @returns {module:mpenc/helper/struct.MiniSet}
         */
        self.or = function(other) {
            var other_items = other.toArray();
            return MiniSet.apply(null, items.concat(other_items));
        };

        /**
         * Return the conjunction of this and another set, i.e. elements that
         * are in this <b>and</b> the other set.
         * @param {module:mpenc/helper/struct.MiniSet} other
         * @returns {module:mpenc/helper/struct.MiniSet}
         */
        self.and = function(other) {
            var other_items = other.toArray();
            return MiniSet.apply(null, items.filter(function(v, i, a){ return other_items.indexOf(v) >= 0; }));
        };

        /**
         * Return the difference of this and another set, i.e. elements that
         * are in this <b>and not</b> the other set.
         * @param {module:mpenc/helper/struct.MiniSet} other
         * @returns {module:mpenc/helper/struct.MiniSet}
         */
        self.andnot = function(other) {
            var other_items = other.toArray();
            return MiniSet.apply(null, items.filter(function(v, i, a){ return other_items.indexOf(v) < 0; }));
        };

        /**
         * Return what was [added, removed] between this and another set, i.e.
         * same as [other.andnot(this), this.andnot(other)].
         * @param {module:mpenc/helper/struct.MiniSet} newer
         * @returns {module:mpenc/helper/struct.MiniSet[]}
         */
        self.changed = function(newer) {
            var newer_items = newer.toArray();
            var removed = items.filter(function(v, i, a){ return newer_items.indexOf(v) < 0; });
            var added = newer_items.filter(function(v, i, a){ return items.indexOf(v) < 0; });
            return [MiniSet.apply(null, added), MiniSet.apply(null, removed)];
        };

        return self;
    };
    /** @class
     * @see module:mpenc/helper/struct#MiniSet */
    ns.MiniSet = MiniSet;

    return ns;
});
