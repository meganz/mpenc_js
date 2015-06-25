/**
 * @fileOverview
 * Test of the `mpenc/impl/session` module.
 */

/*
 * Created: 18 May 2015 Vincent Guo <vg@mega.co.nz>
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
    "mpenc/session",
    "mpenc/impl/session",
    "mpenc/liveness",
    "mpenc/message",
    "mpenc/transcript",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "megalogger",
    "chai",
    "sinon/stub",
], function(ns, impl, liveness, message, transcript, async, struct, utils,
            MegaLogger, chai, stub) {
    "use strict";

    var assert = chai.assert;

    var ImmutableSet = struct.ImmutableSet;

    var M = message.Message;
    var MessageSecurity = message.MessageSecurity;
    var DefaultMessageCodec  = message.DefaultMessageCodec;
    var Payload = message.Payload;
    var ExplicitAck = message.ExplicitAck;
    var Consistency = message.Consistency;

    var MsgAccepted   = transcript.MsgAccepted;
    var NotAccepted   = liveness.NotAccepted;
    var MsgFullyAcked = transcript.MsgFullyAcked;
    var NotFullyAcked = liveness.NotFullyAcked;
    var SNStateChange = ns.SNStateChange;

    var StateMachine = impl.StateMachine;
    var SessionState = ns.SessionState;
    var SessionBase = impl.SessionBase;
    var SessionContext = impl.SessionContext;

    var testTimer;

    beforeEach(function() {
        testTimer = new async.Timer();
    });

    afterEach(function() {
        testTimer.stop();
    });

    var dummyFlowControl = {
        getBroadcastLatency: function() {
            return 5;
        },
        getFullAckInterval: function() {
            return 2 * this.getBroadcastLatency() + 5;
        },
    };

    var dummyMessageSecurity = {
        authEncrypt: function(ts, author, parents, recipients, sectxt) {
            var pubtxt = JSON.stringify({
                author: author,
                parents: parents.toArray(),
                recipients: recipients.toArray(),
                sectxt: sectxt
            });
            return [pubtxt, {
                commit: stub(),
                destroy: stub(),
                mId: utils.sha256(pubtxt),
            }];
        },
        decryptVerify: function(ts, pubtxt, sender) {
            var body = JSON.parse(pubtxt);
            return [body.author, body.parents, body.recipients, body.sectxt, {
                commit: stub(),
                destroy: stub(),
                mId: utils.sha256(pubtxt),
            }];
        },
    };

    var mkSessionBase = function(owner) {
        owner = owner || 51;
        var context = new SessionContext(
            owner, false, testTimer, dummyFlowControl, DefaultMessageCodec, null);

        var members = new ImmutableSet([50, 51, 52]);
        var sId = 's01';
        return new SessionBase(context, sId, members, dummyMessageSecurity);
    };

    describe("SessionBase test", function() {
        it('ctor and stop', function() {
            var sess = mkSessionBase();
            assert.strictEqual(sess.sId(), 's01');
            assert.strictEqual(sess.isConsistent(), true);
            sess.stop();
        });
        it('#_onlyWhileJoined()', function() {
            var sess = mkSessionBase();
            assert.strictEqual(sess._onlyWhileJoined(new Payload("txt")), true);
            assert.strictEqual(sess._onlyWhileJoined(new Consistency(true)), true);
            assert.strictEqual(sess._onlyWhileJoined(new Consistency(false)), false);
            assert.strictEqual(sess._onlyWhileJoined(new ExplicitAck(false)), false);
        });
        it('#_setState()', function() {
            var sess = mkSessionBase();
            var sns = sess._setState(SessionState.PARTED);
            assert.strictEqual(sns.oldState, SessionState.JOINED);
            assert.strictEqual(sns.newState, SessionState.PARTED);
        });
        it('#onEvent()', function() {
            var sess = mkSessionBase();
            var sub = stub();
            var sub1 = stub();
            sess.onEvent(MsgFullyAcked)(sub);
            sess.onEvent(MsgFullyAcked, [303])(sub);
            sess._events.publish(new MsgFullyAcked(301));
            assert(sub.calledOnce);
            assert(sub1.notCalled);
        });
        it('#isConsistent()', function() {
            var sess = mkSessionBase();
            var fullyAcked = stub();
            sess.onEvent(MsgFullyAcked)(fullyAcked);

            assert(fullyAcked.notCalled);
            assert.strictEqual(sess.isConsistent(), true);
            sess._add(M(0, 50, [], [51, 52], new Payload("plaintext 0")), 'ciphertext 0');
            assert.strictEqual(sess.isConsistent(), false);
            sess._add(M(1, 51, [0], [50, 52], new ExplicitAck(true)), 'ciphertext 1');
            assert(fullyAcked.notCalled);
            sess._add(M(2, 52, [1], [50, 51], new ExplicitAck(false)), 'ciphertext 2');
            assert(fullyAcked.calledOnce);
            assert.strictEqual(sess.isConsistent(), true);
        });
        it('consistency monitor auto-acks others\' messges', function(done) {
            var sess = mkSessionBase(51);
            var timer = sess._timer;
            var ts = sess._transcript;
            var notAcked = stub();
            sess._add(M(0, 50, [], [51, 52], new Payload("plaintext 0")), 'ciphertext 0');
            sess.onEvent(NotFullyAcked)(notAcked);
            sess.onSend(stub().returns(true)); // suppress "no subscriber" warnings

            assert(notAcked.notCalled);
            assert.strictEqual(ts.size(), 1);
            assert.strictEqual(sess.isConsistent(), false);
            assert(sess.needAckmon(0));
            assert.deepEqual(ts.unackby(0).toArray(), [51, 52]);
            assert.deepEqual(sess._consistency.active(), [0]);

            timer.after(dummyFlowControl.getFullAckInterval(), function() {
                assert.strictEqual(ts.size(), 2);
                var last = ts.get(ts.max().toArray()[0]);
                assert.strictEqual(last.author, 51);
                assert(last.body instanceof ExplicitAck);
                assert(notAcked.calledOnce);
                timer.after(dummyFlowControl.getFullAckInterval(), function() {
                    // doesn't ack any more
                    assert.strictEqual(ts.size(), 2);
                    sess.stop();
                    done();
                });
            });
        });
        it('#sendData()', function() {
            var sess = mkSessionBase();
            var sendSub = stub().returns(true);
            sess.onSend(sendSub);
            sess.sendData();
            sess.sendData("txt");
            assert.equal(sendSub.callCount, 2);
        });
        it('send-recv round trip', function() {
            var sess0 = mkSessionBase(50), sess1 = mkSessionBase(51);
            var sub0 = stub();
            sess0.onEvent(MsgAccepted)(sub0);
            sess0.onSend(stub().returns(true)); // suppress "no subscriber" warnings
            sess1.onSend(function(send_out) { sess0.recv([send_out[0], 51]); return true; });
            assert(sub0.notCalled);
            sess1.sendData("txt");
            assert(sub0.calledOnce);
        });
        it('send-recv multiple out-of-order packets with dupes', function() {
            var sess0 = mkSessionBase(50),
                sess1 = mkSessionBase(51),
                sess2 = mkSessionBase(52);

            var forSess0 = [];

            sess0.onSend(stub().returns(true)); // suppress "no subscriber" warnings
            sess1.onSend(function(send_out) {
                // send to 52, withhold from 50
                var recv_in = [send_out[0], 51];
                sess2.recv(recv_in);
                forSess0.push(recv_in);
                return true;
            });
            sess2.onSend(function(send_out) {
                // send to 51, withhold from 50
                var recv_in = [send_out[0], 52];
                sess1.recv(recv_in);
                forSess0.push(recv_in);
                return true;
            });

            sess1.sendData("hmm");
            sess2.sendData("what");
            sess1.sendData("who likes ice cream?");
            sess2.sendData("me!");
            sess1.sendData("who wants to kill the president?");
            assert.strictEqual(forSess0.length, 5);

            // http://stackoverflow.com/a/6274381
            var shuffle = function(o) {
                for (var i = o.length; i > 0;) {
                    var j = Math.floor(Math.random() * i);
                    var x = o[--i];
                    o[i] = o[j];
                    o[j] = x;
                }
                return o;
            };
            shuffle(forSess0);

            var accepted = [];
            sess0.onEvent(MsgAccepted)(function(evt) { accepted.push(evt.mId); return true; });

            // send everything to 50
            for (var i = 0; i < forSess0.length; i++) {
                sess0.recv(forSess0[i]);
            }
            assert.strictEqual(accepted.length, 5);

            var ts = sess0.transcript();
            assert.strictEqual(ts.get(accepted[0]).body.content, "hmm");
            assert.strictEqual(ts.get(accepted[3]).body.content, "me!");
            assert.strictEqual(ts.get(accepted[4]).body.content, "who wants to kill the president?");

            // whoops, send some dupes again
            for (var i = 0; i < forSess0.length; i++) {
                sess0.recv(forSess0[i]);
            }
            assert.strictEqual(accepted.length, 5);
        });
        it('#fin() on empty session', function(done) {
            var sess = mkSessionBase();
            var timer = sess._timer;
            sess.onSend(stub().returns(true));
            sess.onFin(function(mId) {
                assert.strictEqual(sess.isConsistent(), true);
                sess.stop();
                timer.after(1, function() {
                    assert.strictEqual(sess.state(), SessionState.PARTED);
                    done();
                });
            });
            sess.fin();
            assert.strictEqual(sess.state(), SessionState.PARTING);
        });
        it('#fin() on inconsistent session', function(done) {
            var sess = mkSessionBase();
            var timer = sess._timer;
            sess._add(M(0, 50, [], [51, 52], new Payload("plaintext 0")), 'ciphertext 0');
            assert.strictEqual(sess.isConsistent(), false);

            sess.onSend(stub().returns(true));
            sess.onFin(function(mId) {
                assert.strictEqual(sess.isConsistent(), false);
                sess.stop();
                timer.after(1, function() {
                    assert.strictEqual(sess.state(), SessionState.PART_FAILED);
                    done();
                });
            });
            sess.fin();
            assert.strictEqual(sess.state(), SessionState.PARTING);
        });
        it('#fin() on consistent non-empty session', function(done) {
            var sess = mkSessionBase();
            var timer = sess._timer;
            sess._add(M(0, 50, [], [51, 52], new Payload("plaintext 0")), 'ciphertext 0');
            assert.strictEqual(sess.isConsistent(), false);

            sess.onSend(stub().returns(true));
            sess.onFin(function(mId) {
                assert.strictEqual(sess.isConsistent(), true);
                sess.stop();
                timer.after(1, function() {
                    assert.strictEqual(sess.state(), SessionState.PARTED);
                    done();
                });
            });
            sess.fin();
            assert.strictEqual(sess.state(), SessionState.PARTING);
            sess._add(M(2, 52, [0], [50, 51], new ExplicitAck(false)), 'ciphertext 2');
        });
        /*it('#updateFreshness()', function() {
            // TODO(xl): do this when we actually implement a PresenceTracker
        });*/
        it('#chainUserEventsTo()', function() {
            var base = mkSessionBase();
            var types = SessionBase.EventTypes;
            var evtctx = new async.EventContext(types);
            var realMessages = new ImmutableSet([0, 3, 4]);
            var sess = { messages: stub().returns(realMessages) };

            var queue = [];
            var watchEvt = function(evt) { queue.push(evt); return true; };
            for (var i = 0; i < types.length; i++) {
                evtctx.subscribe(types[i])(watchEvt);
            }

            base.chainUserEventsTo(sess, evtctx);
            assert.strictEqual(queue.length, 0);
            var chained = function(evt) {
                var old = queue.length;
                base._events.publish(evt);
                return (old === queue.length) ? false : queue.shift() === evt;
            };

            assert.ok(chained(new SNStateChange(SessionState.PARTING, SessionState.JOIN)));

            assert.notOk(chained(new MsgAccepted(0)));
            assert.notOk(chained(new MsgAccepted(1)));
            assert.ok(chained(new NotAccepted(0)));
            assert.ok(chained(new NotAccepted(1)));

            assert.ok(chained(new MsgFullyAcked(0)));
            assert.notOk(chained(new MsgFullyAcked(1)));
            assert.ok(chained(new NotFullyAcked(0)));
            assert.notOk(chained(new NotFullyAcked(1)));

            assert.strictEqual(queue.length, 0);
        });
    });
});
