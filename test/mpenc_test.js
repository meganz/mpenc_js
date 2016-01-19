/**
 * @fileOverview
 * Test of the `mpenc` core module.
 */

/*
 * Created: 27 Aug 2014-2015 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2015 by Mega Limited, Auckland, New Zealand
 *     https://mega.nz/
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
    "mpenc",
    "mpenc/impl/dummy",
    "chai",
], function(ns, dummy, chai) {
    "use strict";

    var assert = chai.assert;

    var pubKeyDir = new Map();

    beforeEach(function() {
        pubKeyDir.clear();
    });

    describe("mpenc core module", function() {
        describe('namespace', function() {
            it('version sub-module', function() {
                assert.notStrictEqual(ns.version, undefined);
            });
        });

        describe('create session', function() {
            it('ctor', function() {
                var server = new dummy.DummyGroupServer();
                var ownKeyPair = ns.createKeyPair();
                pubKeyDir.set("51", ownKeyPair.pubKey);
                var context = ns.createContext(
                    "51", ns.createTimer(), ownKeyPair, pubKeyDir);
                var session = ns.createSession(
                    context, "mpencApiTestSession", server.getChannel("51"));
                assert.deepEqual(session.curMembers().toArray(), ["51"]);
            });

            // once you have created a session, all other tests are as per
            // tests for HybridSession in session_test.js; no point duplicating
            // them here.
        });
    });
});
