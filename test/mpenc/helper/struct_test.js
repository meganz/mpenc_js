/**
 * @fileOverview
 * Tests for `mpenc/helper/struct` module.
 */

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

define([
    "mpenc/helper/struct",
    "chai",
    "asmcrypto",
], function(ns, chai, asmCrypto) {
    "use strict";

    // Shut up warning messages on random number generation for unit tests.
    asmCrypto.random.skipSystemRNGWarning = true;

    var assert = chai.assert;
    var Set = ns.MiniSet;

    describe("MiniSet class", function() {
        describe("constructor, toArray, contains, and equals", function() {
            it("empty set", function() {
                var a = Set();
                assert(a.equals(a));
                assert(a.equals(Set()));
                assert(!a.equals(Set(1)));
                assert(!a.equals(null));
                assert(!a.contains(null));
                assert.sameMembers(a.toArray(), []);
            });
            it("singleton with potentially confusing type", function() {
                var a = Set("3");
                assert(a.equals(a));
                assert(a.equals(Set("3")));
                assert(a.contains("3"));
                assert(!a.equals(Set()));
                assert(!a.equals(Set(3)));
                assert(!a.equals(null));
                assert(!a.contains(3));
                assert.sameMembers(a.toArray(), ["3"]);
                assert.deepEqual(a.toArray(), ["3"]);
                assert.notDeepEqual(a.toArray(), [3]);
            });
            it("general set", function() {
                var a = Set(1, 2, 3);
                assert(a.equals(a));
                assert(a.equals(Set(3, 2, 1)));
                assert(a.equals(Set(2, 3, 1)));
                assert(a.equals(Set(2, 3, 3, 3, 1)));
                assert(a.contains(1));
                assert(a.contains(2));
                assert(a.contains(3));
                assert(!a.equals(Set(2, 1)));
                assert(!a.equals(Set(1, 2, 3, 4)));
                assert(!a.equals(null));
                assert(!a.contains("3"));
                assert(!a.contains("2"));
                assert.sameMembers(a.toArray(), [1, 3, 2]);
            });
        });
        describe("binary operators", function() {
            it("empty set", function() {
               var a = Set(), b = Set();
               assert(a.equals(b));
               assert(a.or(b).equals(b.or(a)));
               assert(a.or(b).equals(a));
               assert(a.or(b).equals(b));
               assert(a.and(b).equals(b.and(a)));
               assert(a.and(b).equals(a));
               assert(a.and(b).equals(b));
               assert(a.andnot(b).equals(b.andnot(a)));
               assert(a.andnot(b).equals(a));
               assert(a.andnot(b).equals(b));
            });
            it("general set", function() {
               var a = Set(1, 2, 3), b = Set(3, 4, 5);
               assert(!a.equals(b));
               assert(a.or(b).equals(b.or(a)));
               assert(!a.or(b).equals(a));
               assert(!a.or(b).equals(b));
               assert(a.or(b).equals(Set(5, 4, 3, 2, 1)));
               assert(a.and(b).equals(b.and(a)));
               assert(!a.and(b).equals(a));
               assert(!a.and(b).equals(b));
               assert(a.and(b).equals(Set(3)));
               assert(!a.andnot(b).equals(b.andnot(a)));
               assert(!a.andnot(b).equals(a));
               assert(!a.andnot(b).equals(b));
               assert(!b.andnot(a).equals(a));
               assert(!b.andnot(a).equals(b));
               assert(a.andnot(b).equals(Set(2, 1)));
               assert(b.andnot(a).equals(Set(5, 4)));
            });
            it("what changed", function() {
               var a = Set(1, 2, 3), b = Set(3, 4, 5);
               var changed_a = a.changed(b);
               var changed_b = b.changed(a);
               assert(changed_a[0].equals(changed_b[1]));
               assert(changed_b[0].equals(changed_a[1]));
               assert(changed_a[0].equals(Set(4, 5)));
               assert(changed_b[0].equals(Set(1, 2)));
            });
        });
    });
});
