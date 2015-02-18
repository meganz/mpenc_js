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
        });
    });
});
