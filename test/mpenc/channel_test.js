/*
 * Created: 3 June 2015 Michael J.L. Holmwood <mh@mega.co.nz>
 *
 * (c) 2014-2016 by Mega Limited, Auckland, New Zealand
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
    "mpenc/impl/channel",
    "mpenc/greet/greeter",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "chai",
    "sinon/stub"
], function(ns, greeter, struct, utils, chai, stub) {
    "use strict";
    var assert = chai.assert;

    var GreetingSummary = greeter.GreetingSummary;
    var GreetingMetadata = greeter.GreetingMetadata;
    var ServerOrder = ns.ServerOrder;
    var ImmutableSet = struct.ImmutableSet;

    // Just a quick function to produce a hash.
    var h = function(value) {
        return utils.sha256(value);
    };

    var postPf = null;
    var postPi = null;

    var resetCallbacks = function() {
        postPf = stub();
        postPi = stub();
    };

    beforeEach(function() {
        resetCallbacks();
    });

    var createDummyMetadata = function(sender) {
        var prevPf = h("prevPf");
        var prevCh = h("prevPf");
        var pmId = [h("pmId")];
        return GreetingMetadata.create(prevPf, prevCh, sender, pmId);
    };

    describe("ServerOrder class", function() {
        var recipients = new ImmutableSet(["1", "2", "3"]);
        var dummyPid = h("pId");

        var acceptOneInitialPacket = function(serverOrder) {
            var metadata = createDummyMetadata("1");
            var summary = GreetingSummary.create(dummyPid, metadata, null, ["1", "2", "3"]);
            var accepted = serverOrder.tryOpPacket("2", summary, recipients,
                    postPi, postPf);

            assert.ok(accepted, "Packet should have been accepted by ServerOrder");
            assert.ok(serverOrder.isSynced());
            assert.ok(serverOrder.hasOngoingOp());
            assert.deepEqual(serverOrder.packetId, [metadata.prevPf, dummyPid]);
            assert.strictEqual(serverOrder.chainHash.length, 2);
            assert.strictEqual(serverOrder.chainHash[0], metadata.prevCh);

            assert.ok(postPi.calledOnce);
            assert.ok(postPf.notCalled);
            assert.strictEqual(postPi.getCall(0).args[0], dummyPid, "pId not correct value.");
            assert.strictEqual(postPi.getCall(0).args[1], metadata.prevPf, "prevPf not correct value.");

            return summary;
        };

        it("_shouldSyncWith, sync true", function() {
            var serverOrder = new ServerOrder();
            var shouldAccept = serverOrder._shouldSyncWith(dummyPid, h("prev"), true);
            assert.ok(shouldAccept);
        });

        it("accepted pi correct, hasSeen true", function() {
            var serverOrder = new ServerOrder();
            acceptOneInitialPacket(serverOrder);
        });

        it("rejected pf, not synced", function() {
            var prevPi = h("prevPi");
            var summary = GreetingSummary.create(dummyPid, null, prevPi, ["1", "2", "3"]);
            var serverOrder = new ServerOrder();
            var accepted = serverOrder.tryOpPacket("2", summary, recipients,
                postPi, postPf);

            assert.notOk(accepted, "Packet should not have been accepted by ServerOrder");
            assert.notOk(serverOrder.isSynced());

            assert.ok(postPf.notCalled);
            assert.ok(postPi.notCalled);
        });

        it("accept pi & pf", function() {
            var prevPi = dummyPid;
            var metadata = createDummyMetadata("1");
            var summary = GreetingSummary.create(dummyPid, metadata, prevPi, ["1", "2", "3"]);
            var serverOrder = new ServerOrder();
            assert.notOk(serverOrder.isSynced());
            var accepted = serverOrder.tryOpPacket("2", summary, recipients,
                postPi, postPf);

            assert.ok(accepted, "Should have accepted pi&pf op");
            assert.ok(serverOrder.isSynced());
            assert.notOk(serverOrder.hasOngoingOp(), "Should have completed pi&pf op in one step");

            assert.ok(postPf.calledOnce);
            assert.ok(postPi.calledOnce);
        });

        it("reject not for us, not synced", function() {
            var metadata = createDummyMetadata("1");
            var summary = GreetingSummary.create(dummyPid, metadata, null, ["1", "3"]);
            var serverOrder = new ServerOrder();
            var accepted = serverOrder.tryOpPacket("2", summary, recipients,
                postPi, postPf);

            assert.notOk(accepted, "Should not have accepted op not for us");
            assert.notOk(serverOrder.isSynced());

            assert.ok(postPf.notCalled);
            assert.ok(postPi.notCalled);

            // see another init pointing to same prev_pF
            var dummyPid2 = h("pId2");
            var summaryTwo = GreetingSummary.create(dummyPid2, metadata, null, ["1", "2", "3"]);
            accepted = serverOrder.tryOpPacket("2", summaryTwo, recipients,
                postPi, postPf);

            assert.notOk(accepted, "Should not have accepted op; we saw an earlier op with the same prevPf not for us");
            assert.notOk(serverOrder.isSynced());

            assert.ok(postPf.notCalled);
            assert.ok(postPi.notCalled);
        });

        it("reject not for us, synced", function() {
            var metadata = createDummyMetadata("1");
            var summary = GreetingSummary.create(dummyPid, metadata, null, ["1", "3"]);
            var serverOrder = new ServerOrder();
            serverOrder.syncNew();
            assert.ok(serverOrder.isSynced());

            var accepted = serverOrder.tryOpPacket("2", summary, recipients,
                postPi, postPf);

            assert.notOk(accepted, "Should not have accepted op not for us");
            assert.notOk(serverOrder.hasOngoingOp());

            assert.ok(postPf.notCalled);
            assert.ok(postPi.notCalled);
        });

        it("reject not in channel", function() {
            var metadata = createDummyMetadata("1");
            var summary = GreetingSummary.create(dummyPid, metadata, null, ["1", "2", "3"]);
            var serverOrder = new ServerOrder();
            var accepted = serverOrder.tryOpPacket("2", summary, new ImmutableSet(["1", "2"]),
                postPi, postPf);

            assert.notOk(accepted, "Should not have accepted op send when members not in channel");
            assert.notOk(serverOrder.isSynced());

            assert.ok(postPf.notCalled);
            assert.ok(postPi.notCalled);

            // later valid packets get accepted
            acceptOneInitialPacket(serverOrder);
        });

        it("recv concurrent proposals", function() {
            var serverOrder = new ServerOrder();
            var summary = acceptOneInitialPacket(serverOrder);
            var metadata = summary.metadata;

            resetCallbacks();
            var dummyPid2 = h("pId2");
            var metadataTwo = createDummyMetadata("3");
            var summaryTwo = GreetingSummary.create(dummyPid2, metadataTwo, null, ["4"]);
            var acceptedFail = serverOrder.tryOpPacket("2", summaryTwo, recipients,
                postPi, postPf);

            assert.notOk(acceptedFail, "Message should not have been accepted.");
            // Verify that none of the state has been changed.
            assert.ok(serverOrder.isSynced());
            assert.ok(serverOrder.hasOngoingOp());
            assert.deepEqual(serverOrder.packetId, [metadata.prevPf, dummyPid]);
            assert.strictEqual(serverOrder.chainHash.length, 2);
            assert.strictEqual(serverOrder.chainHash[0], metadata.prevCh);

            assert.ok(postPf.notCalled, "postPf should not have been called.");
            assert.ok(postPi.notCalled, "postPi should not have been called.");
        });

        it("full cycle", function() {
            // Perform the setup of the serverorder.
            var serverOrder = new ServerOrder();
            var summary = acceptOneInitialPacket(serverOrder);
            var metadata = summary.metadata;

            // Ok, now start the actual test.
            resetCallbacks();

            var newPid = h("pId2");
            // pId of the previous message becomes preId.
            var summaryTwo = GreetingSummary.create(newPid, null, summary.pId, summary.members);
            assert.ok(summaryTwo.isFinal());
            assert.notOk(summaryTwo.isInitial());
            var accepted = serverOrder.tryOpPacket("2", summaryTwo, recipients,
                postPi, postPf);

            assert.ok(accepted, "Message should have been accepted.");
            // Verify that the state changed correctly.
            assert.ok(serverOrder.isSynced());
            assert.notOk(serverOrder.hasOngoingOp(), "ServerOrder should have finished operation.");
            assert.deepEqual(serverOrder.packetId, [metadata.prevPf, dummyPid, newPid]);
            assert.strictEqual(serverOrder.chainHash.length, 3);
            assert.strictEqual(serverOrder.chainHash[0], metadata.prevCh);

            assert.ok(postPf.calledOnce, "postPf should have been called.");
            assert.ok(postPi.notCalled, "postPi should not have been called.");
            assert.strictEqual(postPf.getCall(0).args[0], newPid, "pId not correct value.");
            assert.strictEqual(postPf.getCall(0).args[1], dummyPid, "prevPi not correct value.");

            // Check duplicate not accepted
            accepted = serverOrder.tryOpPacket("2", summaryTwo, recipients,
                postPi, postPf);
            assert.notOk(accepted, "Packet should not be accepted twice");
        });
    });
});
