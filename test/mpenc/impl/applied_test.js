/*
 * Created: 10 Sept 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/impl/applied",
    "mpenc",
    "mpenc/impl/dummy",
    "mpenc/transcript",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "chai",
    "sinon/stub"
], function(ns,
    mpenc, dummy, transcript,
    async, struct, utils,
    chai, stub
) {
    "use strict";
    var assert = chai.assert;

    var ImmutableSet = struct.ImmutableSet;
    var MsgReady = transcript.MsgReady;

    var testTimer;

    beforeEach(function() {
        testTimer = new async.Timer();
    });

    afterEach(function() {
        testTimer.stop();
    });

    var logError = function(e) { console.log(e.stack); };

    var mkHybridSession = function(sId, owner, server, autoIncludeExtra, stayIfLastMember) {
        var context = mpenc.createContext(owner, testTimer, new dummy.DummyFlowControl());
        return mpenc.createSession(context, sId, server.getChannel(owner),
            _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, {
                get: function() { return _td.ED25519_PUB_KEY; }
            }, autoIncludeExtra, stayIfLastMember);
    };

    describe("LocalSendQueue test", function() {
        var execute = function(server, member, action, num) {
            num = num || 4;
            var p = member.execute(action);
            server.runAsync(num, testTimer);
            return !p ? p : p.then(function(result) {
                assert.strictEqual(result, member);
                return result;
            });
        };

        it('offline sending', function() {
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);

            var s1q = new ns.LocalSendQueue(s1);
            var sent, mIds = [];

            sent = s1q.send("testing 1");
            assert.strictEqual(sent.sId, null);
            mIds.push(sent.mId);

            sent = s1q.send("testing 2");
            assert.strictEqual(sent.sId, null);
            mIds.push(sent.mId);

            sent = s1q.send("testing 3");
            assert.strictEqual(sent.sId, null);
            mIds.push(sent.mId);

            assert.strictEqual(new ImmutableSet(mIds).size, 3);
            assert.strictEqual(s1q._findEarliestContinuous(ImmutableSet.EMPTY, s1._ownSet), 0);
        });

        it('autosend after offline', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server, true);
            var s2 = mkHybridSession('myTestSession', "52", server, true);
            var exec = execute.bind(null, server);

            var fakeUI = new Map();
            var s1q = new ns.LocalSendQueue(s1, undefined, undefined, true);
            s1q.onResent(function(evt) {
                assert.ok(evt instanceof ns.MsgResent);
                assert.ok(fakeUI.delete(evt.old_mId));
                assert.notOk(evt.manual);
                if (!fakeUI.size) {
                    done();
                }
            });
            var sent;

            sent = s1q.send("testing 1");
            assert.strictEqual(sent.sId, null);
            fakeUI.set(sent.mId, true);

            sent = s1q.send("testing 2");
            assert.strictEqual(sent.sId, null);
            fakeUI.set(sent.mId, true);

            Promise.resolve(true).then(function() {
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s2, { join: true });
            }).then(function() {
                // onResent handler should eventually fire done()
                return async.timeoutPromise(testTimer, 100);
            }).catch(logError);
        });

        it('autoresend after reconnect', function(done) {
            this.timeout(this.timeout() * 20);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server, true, true);
            var s2 = mkHybridSession('myTestSession', "52", server, true, true);
            var exec = execute.bind(null, server);

            var expecting = new Map();
            var s1q = new ns.LocalSendQueue(s1);
            s1q.onResent(function(evt) {
                assert.ok(evt instanceof ns.MsgResent);
                assert.ok(expecting.delete(evt.old_mId));
                assert.notOk(evt.manual);
            });

            Promise.resolve(true).then(function() {
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s2, { join: true });
            }).then(function() {
                var sent;
                sent = s1q.send("testing 1");
                expecting.set(sent.mId, true);
                sent = s1q.send("testing 2");
                expecting.set(sent.mId, true);
                sent = s1q.send("testing 3");
                expecting.set(sent.mId, true);

                assert.strictEqual(server._incoming.length, 3);
                server._incoming.splice(0, 3); // drop these messages, s2 won't get them
                return exec(s2, { part: true });
            }).then(function() {
                return exec(s2, { join: true });
            }).then(function() {
                // give a bit more time for messages to be delivered
                return async.timeoutPromise(testTimer, 100);
            }).then(function() {
                var mId = s2.messages().slice(-1)[0];
                assert.strictEqual(s2.messages().get(mId).body.content, "testing 3");
                assert.deepEqual(s1.messages().slice(-3), s2.messages().slice());
                done();
            }).catch(logError);
        });
    });

});
