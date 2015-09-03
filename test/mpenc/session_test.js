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
    "mpenc/greet/greeter",
    "mpenc/liveness",
    "mpenc/message",
    "mpenc/transcript",
    "mpenc/impl/dummy",
    "mpenc/impl/transcript",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "megalogger",
    "chai",
    "sinon/stub",
], function(ns, impl, greeter, liveness, message, transcript, dummy, transcriptImpl,
    async, struct, utils,
    MegaLogger, chai, stub
) {
    "use strict";

    var assert = chai.assert;

    var ImmutableSet = struct.ImmutableSet;

    var M = message.Message;
    var MessageSecurity = message.MessageSecurity;
    var DefaultMessageCodec  = message.DefaultMessageCodec;
    var Payload = message.Payload;
    var ExplicitAck = message.ExplicitAck;
    var Consistency = message.Consistency;
    var DefaultMessageLog = transcriptImpl.DefaultMessageLog;
    var MessageSecurity = message.MessageSecurity;

    var MsgAccepted   = transcript.MsgAccepted;
    var NotAccepted   = liveness.NotAccepted;
    var MsgReady      = transcript.MsgReady;
    var MsgFullyAcked = transcript.MsgFullyAcked;
    var NotFullyAcked = liveness.NotFullyAcked;
    var SNState       = ns.SNState;

    var StateMachine = impl.StateMachine;
    var SessionState = ns.SessionState;
    var SessionBase = impl.SessionBase;
    var SessionContext = impl.SessionContext;
    var HybridSession = impl.HybridSession;

    var testTimer;

    beforeEach(function() {
        testTimer = new async.Timer();
    });

    afterEach(function() {
        testTimer.stop();
    });

    var logError = function(e) { console.log(e.stack); };

    var dummyFlowControl = {
        getBroadcastLatency: function() {
            return 5;
        },
        getFullAckInterval: function() {
            return 2 * this.getBroadcastLatency() + 5;
        },
        asynchronity: function() {
            return 3;
        },
    };

    var makeDummyMessageSecurity = function(greetState) {
        var sId = greetState.sessionId;
        return {
            authEncrypt: function(ts, message) {
                var pubtxt = JSON.stringify({
                    sId: btoa(sId),
                    author: message.author,
                    parents: message.parents.toArray().map(btoa),
                    recipients: message.recipients.toArray(),
                    sectxt: btoa(message.body)
                });
                return {
                    pubtxt: pubtxt,
                    secrets: {
                        commit: stub(),
                        destroy: stub(),
                        mId: btoa(utils.sha256(pubtxt)),
                    },
                };
            },
            decryptVerify: function(ts, pubtxt, sender) {
                if (pubtxt.charAt(0) !== "{") {
                    throw new Error("PacketRejected");
                }
                var body = JSON.parse(pubtxt);
                if (atob(body.sId) !== sId) {
                    throw new Error("PacketRejected: not our expected sId " + btoa(sId) + "; actual " + body.sId);
                }
                body.parents = body.parents.map(atob);
                body.body = atob(body.sectxt);
                return {
                    message: body,
                    secrets: {
                        commit: stub(),
                        destroy: stub(),
                        mId: btoa(utils.sha256(pubtxt)),
                    },
                };
            },
        };
    };

    var mkSessionBase = function(owner) {
        owner = owner || "51";
        var context = new SessionContext(
            owner, false, testTimer, dummyFlowControl, DefaultMessageCodec, null);

        var members = new ImmutableSet(["50", "51", "52"]);
        var sId = 's01';
        return new SessionBase(context, sId, members, makeDummyMessageSecurity({ sessionId: sId }));
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
            sess._add(M("0", "50", [], ["51", "52"], new Payload("plaintext 0")), 'ciphertext 0');
            assert.strictEqual(sess.isConsistent(), false);
            sess._add(M("1", "51", ["0"], ["50", "52"], new ExplicitAck(true)), 'ciphertext 1');
            assert(fullyAcked.notCalled);
            sess._add(M("2", "52", ["1"], ["50", "51"], new ExplicitAck(false)), 'ciphertext 2');
            assert(fullyAcked.calledOnce);
            assert.strictEqual(sess.isConsistent(), true);
        });
        it('consistency monitor auto-acks others\' messges', function(done) {
            var sess = mkSessionBase("51");
            var timer = sess._timer;
            var ts = sess._transcript;
            var notAcked = stub();
            sess._add(M("0", "50", [], ["51", "52"], new Payload("plaintext 0")), 'ciphertext 0');
            sess.onEvent(NotFullyAcked)(notAcked);
            sess.onSend(stub().returns(true)); // suppress "no subscriber" warnings

            assert(notAcked.notCalled);
            assert.strictEqual(ts.size(), 1);
            assert.strictEqual(sess.isConsistent(), false);
            assert(sess.needAckmon("0"));
            assert.deepEqual(ts.unackby("0").toArray(), ["51", "52"]);
            assert.deepEqual(sess._consistency.active(), ["0"]);

            timer.after(dummyFlowControl.getFullAckInterval(), function() {
                assert.strictEqual(ts.size(), 2);
                var last = ts.get(ts.max().toArray()[0]);
                assert.strictEqual(last.author, "51");
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
            var sess0 = mkSessionBase("50"), sess1 = mkSessionBase("51");
            var sub0 = stub();
            sess0.onEvent(MsgAccepted)(sub0);
            sess0.onSend(stub().returns(true)); // suppress "no subscriber" warnings
            sess1.onSend(function(send_out) {
                var status = sess0.recv({ pubtxt: send_out.pubtxt, sender: "51" });
                assert.ok(status);
                return true;
            });
            assert(sub0.notCalled);
            sess1.sendData("txt");
            assert(sub0.calledOnce);
        });
        it('send-recv multiple out-of-order packets with dupes', function() {
            var sess0 = mkSessionBase("50"),
                sess1 = mkSessionBase("51"),
                sess2 = mkSessionBase("52");

            var forSess0 = [];

            sess0.onSend(stub().returns(true)); // suppress "no subscriber" warnings
            sess1.onSend(function(send_out) {
                // send to 52, withhold from 50
                var recv_in = { pubtxt: send_out.pubtxt, sender: "51" };
                sess2.recv(recv_in);
                forSess0.push(recv_in);
                return true;
            });
            sess2.onSend(function(send_out) {
                // send to 51, withhold from 50
                var recv_in = { pubtxt: send_out.pubtxt, sender: "52" };
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
            sess._add(M("0", "50", [], ["51", "52"], new Payload("plaintext 0")), 'ciphertext 0');
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
            sess._add(M("0", "50", [], ["51", "52"], new Payload("plaintext 0")), 'ciphertext 0');
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
            sess._add(M("2", "52", ["0"], ["50", "51"], new ExplicitAck(false)), 'ciphertext 2');
        });
        /*it('#updateFreshness()', function() {
            // TODO(xl): do this when we actually implement a PresenceTracker
        });*/
        it('#chainUserEventsTo()', function() {
            var base = mkSessionBase();
            var types = SessionBase.EventTypes;
            var evtctx = new async.EventContext(types);
            var realMessages = new ImmutableSet(["0", "3", "4"]);
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

            assert.ok(chained(new SNState(SessionState.PARTING, SessionState.JOIN)));

            assert.notOk(chained(new MsgAccepted("0")));
            assert.notOk(chained(new MsgAccepted("1")));
            assert.ok(chained(new NotAccepted("0")));
            assert.ok(chained(new NotAccepted("1")));

            assert.ok(chained(new MsgFullyAcked("0")));
            assert.notOk(chained(new MsgFullyAcked("1")));
            assert.ok(chained(new NotFullyAcked("0")));
            assert.notOk(chained(new NotFullyAcked("1")));

            assert.strictEqual(queue.length, 0);
        });
    });

    var mkHybridSession = function(sId, owner, server, autoIncludeExtra, stayIfLastMember) {
        var context = new SessionContext(
            owner, false, testTimer, dummyFlowControl, DefaultMessageCodec, DefaultMessageLog);
        // TODO(xl): replace with a dummy greeter so the tests run quicker
        var dummyGreeter = new greeter.Greeter(owner,
            _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY, {
                get: function() { return _td.ED25519_PUB_KEY; }
            });
        return new HybridSession(context, sId, server.getChannel(owner),
            dummyGreeter, MessageSecurity, autoIncludeExtra, stayIfLastMember);
    };

    describe("HybridSession test", function() {
        var assertSessionStable = function() {
            for (var i = 0; i < arguments.length; i++) {
                var sess = arguments[i];
                assert.strictEqual(sess._ownOperationPr, null,
                    sess._owner + " should not have own operation");
                assert.strictEqual(sess._greeting, null,
                    sess._owner + " should not have greeting");
                assert.strictEqual(sess._ownProposalPr, null,
                    sess._owner + " should not have own proposal");
                assert.strictEqual(sess._taskLeave.size, 0,
                    sess._owner + " should not have any pending taskLeave");
                assert.strictEqual(sess._taskExclude.size, 0,
                    sess._owner + " should not have any pending taskExclude");
                assert.notOk(sess._fubar, sess._owner + " had some internal error");
                assert.ok(!sess._serverOrder.isSynced() || !sess._serverOrder.hasOngoingOp());
            }
        };

        var assertSessionParted = function() {
            for (var i = 0; i < arguments.length; i++) {
                var sess = arguments[i];
                assertMembers([sess._owner], sess);
                assert.strictEqual(sess._curSession, null);
                assert.strictEqual(sess._curGreetState, null);
            }
        };

        var assertSessionState = function(state) {
            for (var i = 1; i < arguments.length; i++) {
                var sess = arguments[i];
                var label = sess.owner() + ":" + btoa(sess.sessionId());
                assert.deepEqual(sess._internalState(), state,
                    "unexpected state from: " + label);
            }
        };

        var assertMembers = function(members) {
            for (var i = 1; i < arguments.length; i++) {
                var sess = arguments[i];
                var label = sess.owner ? sess.owner() + ":" + btoa(sess.sessionId()) : "server";
                assert.deepEqual(arguments[i].curMembers().toArray(), members,
                    "unexpected members from: " + label);
            }
        };

        var execute = function(server, member, action) {
            var p = member.execute(action);
            server.runAsync(16, testTimer);
            return !p ? p : p.then(function(result) {
                assert.strictEqual(result, member);
                return result;
            });
        };

        it('ctor', function() {
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);
            assertMembers([], server);
            assertMembers(["51"], s1);
            assertMembers(["52"], s2);
        });

        it('basic membership changes', function(done) {
            this.timeout(this.timeout() * 30);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);
            var s3 = mkHybridSession('myTestSession', "53", server);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                return exec(s1, { join: true });
            }).then(function() {
                assertSessionState("COsJ", s1);
                assertSessionState("cos_", s2, s3);
                return exec(s1, { include: ["52", "53"] });
            }).then(function() {
                assertMembers(["51", "52", "53"], s1, s2, s3, server);
                assertSessionState("COS_", s1, s2, s3);
                assertSessionStable(s1, s2, s3);
                return exec(s2, { exclude: ["51"] });
            }).then(function() {
                assertMembers(["52", "53"], s2, s3);
                assertSessionState("COS_", s2, s3);
                // it takes a bit more time for s1 to be kicked from the channel
                return async.timeoutPromise(testTimer, 100);
            }).then(function() {
                assertMembers(["52", "53"], server);
                assertMembers(["51"], s1);
                assertSessionState("cos_", s1);
                return exec(s3, { part: true });
            }).then(function() {
                // give some time for leave processes to complete
                return async.timeoutPromise(testTimer, 100);
            }).then(function() {
                assertMembers([], server);
                assertSessionState("cos_", s1, s2, s3);
                assertSessionParted(s1, s2, s3);
                assertSessionStable(s1, s2, s3);
                done();
            }).catch(logError);
        });

        it('sending messages', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s1, { include: ["52"] });
            }).then(function() {
                var testBody = "test message 1230583";
                s1.send({ content: testBody });
                var mId = s1.messages().slice(-1)[0];
                var p = async.newPromiseAndWriters();
                // resolve when other person gets it
                s2.onEvent(MsgReady, [mId])(function(evt) {
                    assert.strictEqual(s2.messages().get(evt.mId).body.content, testBody);
                    p.resolve(evt);
                });
                server.runAsync(16, testTimer);
                return p.promise;
            }).then(function() {
                done();
            }).catch(logError);
        });

        it('pendingGreetPP order-of-processing logic', function(done) {
            this.timeout(this.timeout() * 30);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);
            var s3 = mkHybridSession('myTestSession', "53", server);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s1, { include: ["52", "53"] });
            }).then(function() {
                assertMembers(["51", "52", "53"], s1, s2, s3, server);
                // s1 leaves the channel spontanously, e.g. disconnect
                s1._channel.execute({ leave: true });
                server.recv();
                server.sendAll();
                assertMembers(["52", "53"], server);
                // s1's curSession auto-destroys itself
                assertSessionState("cos_", s1);
                assertSessionParted(s1);
                assertSessionStable(s1);
                // others have started a greeting to exclude s1
                server.recvAll();
                server.sendAll();
                assert.ok(s2._greeting, "expected greeting not started");
                assert.ok(s3._greeting, "expected greeting not started");
                assertSessionState("COS_", s2, s3);
                // run greeting through to completion. but since JS Promises
                // resolve asynchronously, onGreetingComplete() will only fire next tick
                server.run();
                // s1 tries to rejoin the channel
                s1._channel.execute({ enter: true });
                server.recv();
                server.sendAll();
                // if we're not careful, this would throw some async assertion errors
                assertMembers(["51", "52", "53"], server);
                return s3._greeting.getPromise();
            }).then(function() {
                assertMembers(["52", "53"], s2, s3);
                assertSessionStable(s2, s3);
                done();
            }).catch(logError);
        });

        it('concurrent join and auto-leave', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server, true);
            var s2 = mkHybridSession('myTestSession', "52", server, true);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                s1.execute({ join: true });
                return exec(s2, { join: true });
            }).then(function() {
                assertMembers(["51", "52"], server, s1, s2);
                assertSessionState("COS_", s1, s2);
                assertSessionStable(s1, s2);
                return exec(s2, { exclude: ["51"] });
            }).then(function() {
                // give some time for leave processes to complete
                return async.timeoutPromise(testTimer, 100);
            }).then(function() {
                // s2 leaves automatically
                assertMembers([], server);
                assertSessionState("cos_", s1, s2);
                assertSessionParted(s1, s2);
                assertSessionStable(s1, s2);
                done();
            }).catch(logError);
        });

        it('concurrent join, stay-if-last, rejoin with autoinclude', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server, true, true);
            var s2 = mkHybridSession('myTestSession', "52", server, true, true);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                s1.execute({ join: true });
                return exec(s2, { join: true });
            }).then(function() {
                assertMembers(["51", "52"], server, s1, s2);
                assertSessionState("COS_", s1, s2);
                assertSessionStable(s1, s2);
                return exec(s2, { exclude: ["51"] });
            }).then(function() {
                // give some time for leave processes to complete
                return async.timeoutPromise(testTimer, 100);
            }).then(function() {
                // s2 remains in the channel
                assertMembers(["52"], server);
                assertSessionState("cos_", s1);
                assertSessionParted(s1, s2);
                assertSessionStable(s1, s2);
                return exec(s1, { join: true });
            }).then(function() {
                // rejoin works, s2 auto-includes s1
                assertMembers(["51", "52"], server, s1, s2);
                assertSessionState("COS_", s1, s2);
                assertSessionStable(s1, s2);
                done();
            }).catch(logError);
        });

        it('double join', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server, true);
            var s2 = mkHybridSession('myTestSession', "52", server, true);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s2, { join: true });
            }).then(function() {
                assertMembers(["51", "52"], server, s1, s2);
                assertSessionState("COS_", s1, s2);
                assertSessionStable(s1, s2);
                done();
            }).catch(logError);
        });

        it('double join with idle initial users', function(done) {
            this.timeout(this.timeout() * 10);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server); // effectively unresponsive
            var s2 = mkHybridSession('myTestSession', "52", server, true);
            var s3 = mkHybridSession('myTestSession', "53", server, true);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                return exec(s1, { join: true });
            }).then(function() {
                exec(s2, { join: true });
                exec(s3, { join: true });
                // unresponsive user eventually "times out"
                return s1._channel.execute({ leave: true });
            }).then(function() {
                server.runAsync(16, testTimer);
                return s3._ownOperationPr;
            }).then(function() {
                assertMembers(["52", "53"], server, s2, s3);
                assertSessionState("COS_", s2, s3);
                assertSessionStable(s2, s3);
                done();
            }).catch(logError);
        });

        it('quick reinclude', function(done) {
            this.timeout(this.timeout() * 40);
            var server = new dummy.DummyGroupServer();
            var s1 = mkHybridSession('myTestSession', "51", server);
            var s2 = mkHybridSession('myTestSession', "52", server);
            var s3 = mkHybridSession('myTestSession', "53", server);
            var exec = execute.bind(null, server);

            Promise.resolve(true).then(function() {
                assertMembers([], server);
                return exec(s1, { join: true });
            }).then(function() {
                return exec(s1, { include: ["52", "53"] });
            }).then(function() {
                assertMembers(["51", "52", "53"], s1, s2, s3, server);
                assertSessionState("COS_", s1, s2, s3);
                assertSessionStable(s1, s2, s3);
                return exec(s1, { exclude: ["52"] });
            }).then(function() {
                assertMembers(["51", "53"], s1, s3);
                assertSessionState("COS_", s1, s3);
                return exec(s1, { include: ["52"] });
            }).then(function() {
                assertMembers(["51", "52", "53"], s1, s2, s3, server);
                assertSessionState("COS_", s1, s2, s3);
                assertSessionStable(s1, s2, s3);
                return exec(s3, { part: true });
            }).then(function() {
                return exec(s1, { include: ["53"] });
            }).then(function() {
                assertMembers(["51", "52", "53"], s1, s2, s3, server);
                assertSessionState("COS_", s1, s2, s3);
                assertSessionStable(s1, s2, s3);
                done();
            }).catch(logError);
        });
    });
});
