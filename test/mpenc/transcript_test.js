/**
 * @fileOverview
 * Test of the `mpenc/transcript` and `mpenc/impl/transcript` modules.
 */

/*
 * Created: 11 Feb 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Wellsford, New Zealand
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
    "mpenc/transcript",
    "mpenc/impl/transcript",
    "mpenc/message",
    "chai"
], function(ns, impl, message,
            chai) {
    "use strict";

    var assert = chai.assert;

    var checkAdd = function(transcript, msg) {
        transcript.add(msg);
        //Transcript.checkInvariants(transcript);
        //CausalOrder.checkInvariants(transcript);
    };

    var M = message.Message;

    describe("BaseTranscript class", function() {
        it('empty object', function() {
            var tr = new impl.BaseTranscript();
            // TODO(xl): write these invariant checks in the interface class
            //Transcript.checkInvariants(test);
            //CausalOrder.checkInvariants(test);
            checkAdd(tr, M(0, 50, [], []));
            assert(tr.unackby(0).size === 0);
            assert(tr.unacked().length === 0);
        });

        it('smoke test, various features', function() {
            var tr = new impl.BaseTranscript();
            //Transcript.checkInvariants(test);
            //CausalOrder.checkInvariants(test);

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
    });
});
