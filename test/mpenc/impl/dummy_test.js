/*
 * Created: 10 Jul 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/impl/dummy",
    "mpenc/helper/struct",
    "chai"
], function(ns, struct, chai) {
    "use strict";

    var assert = chai.assert;

    var ImmutableSet = struct.ImmutableSet;

    describe("DummyGroupServer class", function() {
        var assertMembersConsistent = function(server, users, members) {
            assert.deepEqual(server.curMembers().toArray(), members);
            members.forEach(function(id) {
                assert.deepEqual(server.getChannel(id).curMembers().toArray(), members);
            });
            ImmutableSet.from(users).subtract(ImmutableSet.from(members)).forEach(function(id) {
                assert.deepEqual(server.getChannel(id).curMembers(), null);
            });
        };

        it("ctor and basic membership", function() {
            var server = new ns.DummyGroupServer();
            var c0 = server.getChannel(0);
            var c1 = server.getChannel(1);
            var c2 = server.getChannel(2);

            assert.deepEqual(server.curMembers().toArray(), []);
            assert.deepEqual(c0.curMembers(), null);
            assert.deepEqual(c1.curMembers(), null);
            assert.deepEqual(c2.curMembers(), null);
        });

        it("basic membership changes", function() {
            var server = new ns.DummyGroupServer();
            var all = [0, 1, 2];
            var c0 = server.getChannel(0);
            var c1 = server.getChannel(1);
            var c2 = server.getChannel(2);

            c0.send({ enter: true });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [0]);

            c1.send({ enter: true });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [0, 1]);

            c1.send({ enter: [2] });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [0, 1, 2]);

            c2.send({ leave: [1] });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [0, 2]);

            c0.send({ enter: [1], leave: [2] });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [0, 1]);

            c0.send({ leave: true });
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [1]);

            c2.send({ enter: [0], leave: [1] }); // not in channel, no effect
            server.recv();
            server.sendAll();
            assertMembersConsistent(server, all, [1]);
        });

        it("server kick races", function() {
            var server = new ns.DummyGroupServer();
            var all = [0, 1];
            var c0 = server.getChannel(0);
            var c1 = server.getChannel(1);

            var joinAll = function() {
                c0.packetsReceived = 0;
                c1.packetsReceived = 0;
                c0.send({ enter: true });
                c1.send({ enter: true });
                server.recvAll();
                server.sendAll();
                assertMembersConsistent(server, all, all);
            };

            var sendSequence = function() {
                c0.send({ leave: [1] });
                c0.send({ pubtxt: "message 0", recipients: ImmutableSet.from(all) });
                c1.send({ leave: [0] });
                c1.send({ pubtxt: "message 1", recipients: ImmutableSet.from(all) });
            };

            joinAll();
            sendSequence();
            // 0's packet gets processed first
            server.recv(0);
            server.run();
            // 0 remains in channel
            assertMembersConsistent(server, all, [0]);
            assert.strictEqual(c0.packetsReceived, 1);
            assert.strictEqual(c1.packetsReceived, 0);

            joinAll();
            sendSequence();
            // 1's packet gets processed first
            server.recv(2);
            server.run();
            // 1 remains in channel
            assertMembersConsistent(server, all, [1]);
            assert.strictEqual(c0.packetsReceived, 0);
            assert.strictEqual(c1.packetsReceived, 1);
        });

        it("execute() Promise resolution", function(done) {
            var server = new ns.DummyGroupServer();
            var exec = function(id, action) {
                var ch = server.getChannel(id);
                var p = ch.execute(action);
                server.run(); // run the dummy-server, promise should resolve in next tick
                return !p ? p : p.then(function(result) {
                    assert.strictEqual(result, ch);
                    return result;
                });
            };
            var all = [0, 1, 2];

            // basically the same as "basic membership changes"
            Promise.resolve(true).then(function() {
                assertMembersConsistent(server, all, []);
                return exec(0, { enter: true });
            }).then(function() {
                assertMembersConsistent(server, all, [0]);
                return exec(1, { enter: true });
            }).then(function() {
                assertMembersConsistent(server, all, [0, 1]);
                return exec(1, { enter: [2] });
            }).then(function() {
                assertMembersConsistent(server, all, [0, 1, 2]);
                return exec(2, { leave: [1] });
            }).then(function() {
                assertMembersConsistent(server, all, [0, 2]);
                return exec(0, { enter: [1], leave: [2] });
            }).then(function() {
                assertMembersConsistent(server, all, [0, 1]);
                return exec(0, { leave: true });
            }).then(function() {
                assertMembersConsistent(server, all, [1]);
                return exec(2, { enter: [0], leave: [1] }); // not in channel, no effect
            }).then(function() {
                assertMembersConsistent(server, all, [1]);
                done();
            }).catch(console.log);
        });
    });
});

