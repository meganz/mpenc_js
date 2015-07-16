/*
 * Created: 7 May 2015 Vincent Guo <vg@mega.co.nz>
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
    "mpenc/channel",
    "mpenc/greet/greeter",
    "mpenc/liveness",
    "mpenc/message",
    "mpenc/transcript",
    "mpenc/impl/channel",
    "mpenc/impl/liveness",
    "mpenc/impl/transcript",
    "mpenc/helper/assert",
    "mpenc/helper/struct",
    "mpenc/helper/async",
    "mpenc/helper/utils",
    "promise-polyfill",
    "megalogger"
], function(session, channel, greeter, liveness, message, transcript,
    channelImpl, livenessImpl, transcriptImpl,
    assert, struct, async, utils, Promise, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/impl/session
     * @description
     * Session related operations
     */
    var ns = {};

    var logger = MegaLogger.getLogger("session", undefined, "mpenc");
    var _assert = assert.assert;

    // import events
    var MsgAccepted   = transcript.MsgAccepted;
    var NotAccepted   = liveness.NotAccepted;
    var MsgFullyAcked = transcript.MsgFullyAcked;
    var NotFullyAcked = liveness.NotFullyAcked;
    var SNStateChange = session.SNStateChange;
    var SessionState = session.SessionState;
    var SNMembers = session.SNMembers;
    var NotDecrypted = session.NotDecrypted;

    // import components
    var Session = session.Session;
    var Flow = liveness.Flow;
    var BaseTranscript = transcriptImpl.BaseTranscript;
    var DefaultConsistencyMonitor = livenessImpl.DefaultConsistencyMonitor;
    var ServerOrder = channelImpl.ServerOrder;

    // import message-types
    var Message = message.Message;
    var Payload = message.Payload;
    var ExplicitAck = message.ExplicitAck;
    var Consistency = message.Consistency;
    var GreetingMetadata = greeter.GreetingMetadata;

    // import utils
    var Observable = async.Observable;
    var Subscribe = async.Subscribe;
    var EventContext = async.EventContext;
    var ImmutableSet = struct.ImmutableSet;
    var TrialTimeoutTarget = struct.TrialTimeoutTarget;
    var TrialBuffer = struct.TrialBuffer;
    var StateMachine = utils.StateMachine;


    /**
     * Context of a session.
     *
     * @class
     * @memberOf module:mpenc/impl/session
     */
    var SessionContext = struct.createTupleClass("owner", "keepfresh", "timer", "flowctl", "codec", "makeMessageLog");

    Object.freeze(SessionContext.prototype);
    ns.SessionContext = SessionContext;


    /**
     * Implementation of roughly the lower (transport-facing) part of Session.
     *
     * <p>Manages operations on the causally-ordered transcript data structure,
     * flow control algorithms, message security, consistency checking, etc.</p>
     *
     * The instantiated types for <code>SendingReceiver</code> are:
     *
     * <ul>
     * <li><code>{@link module:mpenc/impl/session.SessionBase#recv|RecvInput}</code>:
     *      {@link module:mpenc/helper/utils~RawRecv}</li>
     * <li><code>{@link module:mpenc/impl/session.SessionBase#onSend|SendOutput}</code>:
     *      {@link module:mpenc/helper/utils~RawSend}</li>
     * </ul>
     *
     * @class
     * @memberOf module:mpenc/impl/session
     * @implements {module:mpenc/liveness.Flow}
     * @implements {module:mpenc/helper/async.EventSource}
     * @implements {module:mpenc/helper/utils.SendingReceiver}
     * @param context {module:mpenc/impl/session.SessionContext} Session context.
     * @param sId {string} Session id, shared between all members.
     * @param members {module:mpenc/helper/struct.ImmutableSet} Set of members.
     * @param msgsec {module:mpenc/message.MessageSecurity} Security component.
     * @see module:mpenc/session.Session
     */
    var SessionBase = function(context, sId, members, msgsec) {
        this.options = {
            /**
             * Ratio of heartbeat interval to the full-ack-interval
             * How long to wait when we are idle, before sending a heartbeat.
             */
            HEARTBEAT_RATIO : 4,

            /**
             * Ratio of fin consistency timeout to the broadcast-latency
             * How long to wait for consistency, before we publish that fin() completed with inconsistency.
             */
            FIN_TIMEOUT_RATIO : 16,

            /**
             * Ratio of fin consistency grace-wait to the broadcast-latency
             * How long to wait after consistency is reached, before we publish that fin() completed with consistency.
             */
            FIN_CONSISTENT_RATIO : 1,

            /**
             * Give others a little bit longer than ourselves to expire freshness.
             */
            EXPIRE_GRACE_RATIO : 1.0625
        };

        this._stateMachine = new StateMachine(SNStateChange, SessionState.JOINED);
        this._events = new EventContext(SessionBase.EventTypes);

        this._owner = context.owner;
        this._sId = sId;
        this._transcript = new BaseTranscript();
        this._transcript_add = this._transcript.add.bind(this._transcript);
        Object.defineProperty(this._transcript, "add", {
            value: function() { throw new Error("forbidden"); }
        });

        this._timer = context.timer;
        this._ctime = new Map();
        this._ktime = new Map();

        this._send = new async.Observable(true);
        var cancels = [];

        this._members = members;
        this._msgsec = msgsec;

        var self = this;
        this._flowctl = context.flowctl;
        this._consistency = new DefaultConsistencyMonitor(
            context.owner, context.timer,
            this._onFullAck.bind(this),
            this._fullAckInterval.bind(this),
            function(mId) { self._events.publish(new NotFullyAcked(mId)); },
            this.needAckmon.bind(this),
            this._transcript.unackby.bind(this._transcript),
            this._generateMonitorIntervals.bind(this),
            function() {},
            this._handleUnackedByOwn.bind(this));

        this._codec = context.codec;
        var tryAccept = new TrialTimeoutTarget(
            context.timer, this._broadcastLatency(),
            this._tryAcceptTimeout.bind(this),
            {
                maxSize: this._expectedMaxBuf.bind(this),
                paramId: function(param) { return utils.sha256(param[1]); },
                tryMe: this._tryAcceptTry.bind(this),
                cleanup: this._tryAcceptCleanup.bind(this),
            });
        this._tryAccept = new TrialBuffer('try-accept for ' + this._sId, tryAccept);

        this._fin = new Observable();
        this._pubtxt = new Map(); /* ciphertxt cache, mId->pubtxt and pubtxt->mId*/

        this._cancels = async.combinedCancel(cancels);
    };

    SessionBase.EventTypes = [SNStateChange, MsgAccepted, MsgFullyAcked, NotAccepted, NotFullyAcked];

    SessionBase.prototype._expectedMaxBuf = function() {
        return 4 * Math.max(16, Math.sqrt(this.curMembers().size) * 8);
    };

    SessionBase.prototype._onlyWhileJoined = function(body) {
        return (body instanceof Payload || Consistency.isFin(body));
    };

    SessionBase.prototype._broadcastLatency = function(r) {
        r = r || 1;
        return r * this._flowctl.getBroadcastLatency();
    };

    SessionBase.prototype._fullAckInterval = function(mId, r) {
        r = r || 1;
        return r * this._flowctl.getFullAckInterval(this, mId);
    };

    SessionBase.prototype._onFullAck = function(mId) {
        var sub_evt = this._events.subscribe(MsgFullyAcked, [mId]);
        return Subscribe.wrap(function(sub) {
            return sub_evt(function(evt) { return sub(evt.mId); });
        });
    };

    // This will eventually be part of a FlowControl interface/implementation
    SessionBase.prototype._generateMonitorIntervals = function(mId) {
        return struct.toIterator(
            this.owns(mId) ? [] : [this._fullAckInterval(mId) - this._broadcastLatency()]);
    };

    // This will eventually be part of a FlowControl interface/implementation
    SessionBase.prototype._handleUnackedByOwn = function(mId) {
        _assert(!this.owns(mId) && this.transcript().suc_ruId(mId, this.owner()) === null);
        _assert(this.transcript().has(mId));
        var sent = this.sendObject(new ExplicitAck(false));
        _assert(sent && this.transcript().suc_ruId(mId, this.owner()) !== null);
    };

    // In the python, these form part of the Membership interface, which is
    // not currently needed in this library since we use HybridSession exclusively
    SessionBase.prototype._membersAfter = function(transcript, parents) {
        return this._members;
    };

    // In the python, these form part of the Membership interface, which is
    // not currently needed in this library since we use HybridSession exclusively
    SessionBase.prototype._membersChangedBy = function(transcript, membersBefore, msg) {
        _assert(membersBefore.equals(this._members),
            'members is not equal to members before');
        if (!membersBefore.equals(msg.members())) {
            throw new Error("msg has unexpected members: expected " + membersBefore +
                            ", actual " + msg.members());
        }
        return ImmutableSet.EMPTY_DIFF;
    };

    /**
     * @returns {string} A short summary of this session.
     */
    SessionBase.prototype.toString = function() {
        return this._owner + ":" + btoa(this._sId.substring(0, 3)) + ":[" + this.curMembers().toArray() + "]";
    };

    // "implements" StateMachine

    /**
     * Get the current state.
     * @returns {SessionState}
     */
    SessionBase.prototype.state = function() {
        return this._stateMachine.state();
    };

    SessionBase.prototype._setState = function(newState) {
        // set the state of the internal FSM, and return a transition event
        // object to be published to our subscribers
        var chg = this._stateMachine.setState(newState);
        this._events.publish(chg);
        return chg;
    };

    // implements EventSource

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.onEvent = function(evtcls, prefix, useCapture) {
        return this._events.subscribe(evtcls, prefix, useCapture);
    };

    // implements Flow

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.owner = function()  {
        return this._owner;
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.transcript = function() {
        return this._transcript;
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.curMembers = function() {
        return this._membersAfter(this._transcript, this._transcript.max());
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.ctime = function(mId) {
        return struct.safeGet(this._ctime, mId);
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.ktime = function(mId) {
        return struct.safeGet(this._ktime, mId);
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.needAckmon = function(mId) {
        return !(this._transcript.get(mId).body instanceof ExplicitAck);
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.owns = Flow.prototype.owns;

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.lastOwnMsg = Flow.prototype.lastOwnMsg;

    // implements SendingReceiver; also helps to implement Session

    /**
     * @returns {string} Session Id.
     */
    SessionBase.prototype.sId = function() {
        return this._sId;
    };

    /**
     * Returns whether our session transcript is consistent with ours.
     * @returns {boolean}
     */
    SessionBase.prototype.isConsistent = function() {
        var self = this;
        return !this._transcript.unacked().some(function(mId) {
            return self._transcript.get(mId).body instanceof Payload;
        });
    };

    /**
     * Send application-level data.
     *
     * @param contents {?string}
     * @returns {boolean} Whether the contents were accepted to be sent.
     */
    SessionBase.prototype.sendData = function(contents) {
        // TODO(xl): [F] if we "recently" (e.g. <1s ago) accepted a message, the
        // user is unlikely to have fully-understood it. so perhaps we should
        // actually only point to non-recent messages as the "parent" messages.
        return this.sendObject((contents) ? new Payload(contents) : new ExplicitAck(true));
    };

    /**
     * @method
     * @inheritDoc
     */
    SessionBase.prototype.sendObject = function(body) {
        if ((this._stateMachine.state() !== SessionState.JOINED) &&
             this._onlyWhileJoined(body)) {
            return false;
        }
        var ts = this.transcript();
        var author = this.owner();
        var parents = ts.max();
        var recipients = this.curMembers().subtract(new ImmutableSet([author]));

        // function(body, recipients, parents, paddingSize)
        var sectxt = this._codec.encode(body);
        var enc = this._msgsec.authEncrypt(ts, author, parents, recipients, sectxt);
        var pubtxt = enc[0], secret = enc[1];

        var mId = secret.mId;
        var msg = new Message(mId, author, parents, recipients, body);
        try {
            this._add(msg, pubtxt);
            secret.commit();
        } catch (e) {
            secret.destroy();
            this._handleInvalidMessage(mId, author, parents, recipients, e);
            return false;
        }

        var stat = this._send.publish({ pubtxt: pubtxt, recipients: recipients });
        return stat.some(Boolean);
    };

    /**
     * @inheritDoc
     */
    SessionBase.prototype.recv = function(recv_in) {
        var pubtxt = recv_in.pubtxt;
        var sender = recv_in.sender;
        var mId = this._pubtxt.get(pubtxt);
        if (mId) {
            // duplicate received
            return true;
        }
        try {
            var dec = this._msgsec.decryptVerify(this._transcript, pubtxt, sender);
            var author = dec[0], parents = dec[1], recipients = dec[2],
                sectxt = dec[3], secret = dec[4];
            mId = secret.mId;
        } catch (e) {
            return false;
        }
        _assert(author !== this.owner(), 'received non-duplicate message from self: ' + btoa(mId));

        try {
            var body = this._codec.decode(sectxt);
        } catch (e) {
            secret.destroy();
            this._handleInvalidMessage(mId, author, parents, recipients, e);
            return true; // decrypt succeeded so message was indeed properly part of the session
        }

        var msg = new Message(mId, author, parents, recipients, body);
        this._tryAccept.trial([msg, pubtxt, secret]);
        return true;
    };

    /**
     * @inheritDoc
     */
    SessionBase.prototype.onSend = function(send_out) {
        return this._send.subscribe(send_out);
    };

    SessionBase.prototype._handleInvalidMessage = function(mId, author, parents, recipients, error) {
        // TODO(xl): [D/F] more specific handling of:
        // - message decode error
        // - total-order breaking
        // - transitive-reduction breaking
        // - bad membership change
        // TODO(xl): [F] (invalid-msg) also should emit error message and shutdown the session
        logger.warn('BAD MESSAGE (malicious/buggy peer?) in verified-decrypted msg ' +
            btoa(mId) + ' : ' + error);
    };

    SessionBase.prototype._tryAcceptCleanup = function(replace, param) {
        var secret = param[2];
        if (!replace) {
            secret.destroy();
        }
    };

    SessionBase.prototype._tryAcceptTimeout = function(param) {
        var msg = param[0], pubtxt = param[1];
        this._events.publish(new NotAccepted(msg.author, msg.parents));
    };

    SessionBase.prototype._tryAcceptTry = function(_, param) {
        var msg = param[0], pubtxt = param[1], secret = param[2];

        // a slight hack, works because Transcript implements "has" which subtract needs
        var diff = msg.parents.subtract(this._transcript);
        if (diff.size > 0) {
            // parents not yet all received
            return false;
        }

        try {
            var mId = msg.mId;
            this._add(msg, pubtxt);
            secret.commit();
            return true;
        } catch (e) {
            secret.destroy();
            this._handleInvalidMessage(msg.mId, msg.author, msg.parents, msg.recipients, e);
            return true; // message was accepted as invalid, don't buffer again
        }
    };

    SessionBase.prototype._add = function(msg, pubtxt) {
        var self = this;
        var ts = this.transcript();
        var membersBefore = this._membersAfter(ts, msg.parents);
        var intendedDiff = this._membersChangedBy(ts, membersBefore, msg);

        var fullAcked = this._transcript_add(msg);
        // from this point onwards, should be no exceptions raised

        var mId = msg.mId;
        var tick = this._timer.now();

        this._pubtxt.set(pubtxt, mId);
        this._pubtxt.set(mId, pubtxt);
        this._ctime.set(mId, tick);
        this._ktime.set(mId, null);
        for (var i = 0; i < fullAcked.length; i++) {
            this._ktime.set(fullAcked[i], tick);
        }

        this._consistency.expect(mId);
        this._events.subscribe(MsgFullyAcked, [mId])(function(evt) {
            var mId = evt.mId;
            self._pubtxt.delete(mId);
            // this._pubtxt.delete(pubtxt);
            // TODO(xl): [D] this is hard to get right; see python for ideas
        });

        this._events.publish(new MsgAccepted(mId));
        for (var i = 0; i < fullAcked.length; i++) {
            this._events.publish(new MsgFullyAcked(fullAcked[i]));
        }
    };

    // other own public methods

    /**
     * Send a close message, delegating to send(). Stop any heartbeats, and
     * wait for consistency to be reached. When this is reached or times out,
     * sub_fin() subscribers will be notified.
     *
     * No Payload may be sent after this is called.
     *
     * @returns {boolean} whether this operation was appropriate at this time
     */
    SessionBase.prototype.fin = StateMachine.transition(
        [SessionState.JOINED],
        [SessionState.JOINED, SessionState.PARTING], function() {

        if (!this.sendObject(new Consistency(true))) {
            return false;
        }

        // TODO(xl): [D/F] if transcript is empty, perhaps make this a no-op
        var ts = this.transcript();
        _assert(ts.max().size === 1);
        var mId = ts.max().toArray()[0];
        this._setState(SessionState.PARTING);

        var self = this;
        var _pubFin = function() {
            self.stop();
            self._fin.publish(mId);
            if (self.isConsistent()) {
                self._setState(SessionState.PARTED);
            } else {
                self._setState(SessionState.PART_FAILED);
            }
        };
        var finTimeout = this._broadcastLatency(this.options.FIN_TIMEOUT_RATIO);
        var finConsistent = this._broadcastLatency(this.options.FIN_CONSISTENT_RATIO);
        this._events.subscribe(MsgFullyAcked, [mId]).withBackup(
            this._timer.after(finTimeout), _pubFin)(function(evt) {
            self._timer.after(finConsistent, _pubFin);
        });

        return true;
    });

    /**
     * Subscribe to notices that fin() reached consistency or timed out.
     *
     * Note: subscriptions are fired *before* any state() changes.
     */
    SessionBase.prototype.onFin = function(sub) {
        return this._fin.subscribe(sub);
    };

    /**
     * Stop running monitors, close resources, cancel subscriptions.
     */
    SessionBase.prototype.stop = function() {
        var ts = this.transcript();
        _assert(new ImmutableSet(this._consistency.active()).equals(
                new ImmutableSet(ts.unacked())), 'unmatched keys');
        this._consistency.stop();
        this._cancels();
    };

    /**
     * Update the presence of a user, based on a MsgAccepted event.
     * @param {type} presence
     * @param {type} evt
     */
    SessionBase.prototype.updateFreshness = function(presence, evt) {
        var mId = evt.mId;
        var msg = this._transcript.get(mId);
        var uId = msg.author;
        var own = (uId === this.owner());
        // last own message that this message was sent after
        var lastOwn = own ? mId : this._transcript.pre_ruId(mId, this.owner());
        // TODO(xl): [F/D] need some other mechanism to determine known_ts if there is no own last message
        var knownTs = lastOwn ? this.ctime.get(lastOwn) : 0;
        var expireAfter = this._fullAckInterval(mId, this.options.HEARTBEAT_RATIO);
        presence.renew(uId, knownTs,
                       own ? expireAfter : expireAfter * this.options.EXPIRE_GRACE_RATIO);
        // if message is Consistency(close=True) then set UserAbsent(intend=True) on full-ack
        if (Consistency.isFin(msg.body)) {
            this._events.subscribe(MsgFullyAcked, [mId])(function() {
                presence.absent(uId, knownTs);
            });
        }
    };

    /**
     * Ticks after which we should assume others expire our own presence.
     */
    SessionBase.prototype.ownExpiry = function() {
        return this._fullAckInterval(this.lastOwnMsg(), this.options.HEARTBEAT_RATIO);
    };

    /**
     * Fire user-relevant events from here into an actual Session.
     */
    SessionBase.prototype.chainUserEventsTo = function(sess, evtctx) {
        var special = new ImmutableSet([MsgAccepted, NotFullyAcked, MsgFullyAcked]);
        var evtcls = this._events.evtcls().subtract(special);
        var cancel_else = evtctx.chainFrom(this._events, evtcls);

        // - ignore MsgAccepted; assume something else is already firing MsgReady
        // - forward *all* NotAccepted, since they might indicate missing Payload messages
        // - forward NotFullyAcked / MsgFullyAcked only for Payload messages

        var cancel_onNotFullyAcked = this._events.subscribe(NotFullyAcked)(function(evt) {
            if (sess.messages().has(evt.mId)) {
                evtctx.publish(evt);
            }
        });

        var cancel_onMsgFullyAcked = this._events.subscribe(MsgFullyAcked)(function(evt) {
            if (sess.messages().has(evt.mId)) {
                evtctx.publish(evt);
            }
        });

        return async.combinedCancel([
            cancel_else, cancel_onNotFullyAcked, cancel_onMsgFullyAcked]);
    };

    ns.SessionBase = SessionBase;


    var OwnOp = struct.createTupleClass("action", "include", "exclude");

    /**
     * A Session with a linear order on its membership operations.
     *
     * @class
     * @memberOf module:mpenc/impl/session
     * @implements {module:mpenc/session.Session}
     * @param context {module:mpenc/impl/session.SessionContext} Session context.
     * @param sId {string} Session id, shared between all members.
     * @param channel {module:mpenc/channel.GroupChannel} Group transport channel.
     * @param greeter {module:mpenc/greet/greeter.Greeter} Membership operation component.
     * @param makeMessageSecurity {function} 1-arg factory function for a
     *      {@link module:mpenc/message.MessageSecurity}.
     */
    var HybridSession = function(context, sId, channel, greeter, makeMessageSecurity) {
        this._context = context;
        this._events = new EventContext(Session.EventTypes);

        this._owner = context.owner;
        this._ownSet = new ImmutableSet([this._owner]);
        this._sId = sId;
        this._channel = channel;

        this._timer = context.timer;
        var cancels = [];

        this._flowctl = context.flowctl;

        this._messages = context.makeMessageLog();
        cancels.push(this._messages.bindTarget(this._events));

        this._greeter = greeter;
        this._makeMessageSecurity = makeMessageSecurity;

        // sub-sessions
        this._curSession = null;
        this._curSessionCancel = null;
        this._curGreetState = null;
        this._prevSession = null;
        this._prevSessionCancel = null;
        this._prevGreetState = null;
        this._droppedInconsistentSession = false;

        // sub-session send/recv logic
        cancels.push(this._channel.onRecv(this._recv.bind(this)));
        this._sessionRecv = new Observable(); // for sub-sessions to listen on, filters out greeting packets
        var tryDecrypt = new TrialTimeoutTarget(
            this._timer, this._flowctl.getBroadcastLatency(),
            this._tryDecryptTimeout.bind(this),
            {
                maxSize: this._flowctl.asynchronity.bind(this._flowctl, this),
                paramId: function(recv_in) { return utils.sha256(recv_in.pubtxt); },
                tryMe: this._tryDecryptTry.bind(this)
            });
        this._tryDecrypt = new TrialBuffer('try-decrypt for ' + this.sId, tryDecrypt);

        // global ops
        this._serverOrder = new ServerOrder();
        this._channelJustSynced = false;
        this._greeting = null;
        this._clearChannelRecords();
        this._greetingCancel = function() {};
        this._clearGreeting();

        this._clearOwnProposal();
        this._clearOwnOperation();

        this._cancel = async.combinedCancel(cancels);
    };

    /* Summary of the internal state of the session.
     *
     * "Unstable" means that we are expecting the state to change automatically
     * without human intervention e.g. due to timeouts and/or other reactive
     * behaviours such as key agreement responses. "Stable" means that we don't
     * have such an expectation.
     */
    HybridSession.prototype._internalState = function() {
        if (!this._channel.curMembers()) {
            _assert(!this._serverOrder.isSynced());
            _assert(!this._curSession);
            // Not in the channel. Stable.
            return "cos_";
        } else if (!this._serverOrder.isSynced()) {
            _assert(!this._curSession);
            // In the channel, ServerOrder unsynced. Unstable; others should
            // cause us to be synced later, expecting COsj.
            return "Cos_";
        } else if (!this._curSession) {
            // In the channel, ServerOrder synced, but no session.
            if (this._channelJustSynced) {
                _assert(this._channel.curMembers().equals(this._ownSet));
                // Stable; we just entered the channel and we're the only ones here.
                return "COsJ";
            } else {
                // Unstable; one of:
                // - (greeting !== null): we entered the channel, and just
                //   accepted a greeting, but it's not yet complete -> COS_
                // - (greeting === null &! serverOrder.isSynced()): we entered
                //   the channel, and have not yet synced with others -> COsJ
                // - (greeting === null && serverOrder.isSynced()): we just
                //   completed a _changeMembership that implicitly excluded
                //   everyone else, but we haven't yet left the channel, so as
                //   to wait for consistency -> cos_
                return "COsj";
            }
        } else {
            // In the channel, ServerOrder synced, with session. Stable.
            return "COS_";
        }
    };

    HybridSession.prototype._clearChannelRecords = function(r) {
        this._serverOrder.clear();
        this._channelJustSynced = false;
        this._taskExclude = new Set();
        this._taskLeave = new Set();
        return async.exitFinally(r);
    };

    HybridSession.prototype._clearGreeting = function(r) {
        this._greetingCancel();
        this._greetingCancel = null;
        this._greeting = null;
        if (r instanceof Error && typeof r.message === "string" &&
            r.message.indexOf("OperationIgnored:") === 0) {
            logger.info(r.message);
            return null;
        }
        return async.exitFinally(r);
    };

    HybridSession.prototype._setGreeting = function(greeting) {
        this._greeting = greeting;
        this._greetingCancel = greeting.onSend(this._channel.send.bind(this._channel));
        var p = greeting.getPromise();
        var clear = this._clearGreeting.bind(this);
        var self = this;
        // JS promises resolve asynchronously; if we split this into two .then()s then things break
        p.then(function(greeting) { return self._changeSubSession(self._onGreetingComplete(greeting)); })
         .then(clear, clear)
         .catch(logger.warn.bind(logger));
        // greeting accepted, try to achieve consistency in case this succeeds
        // and we need to rotate the sub-session
        if (this._curSession && this._curSession.state() === SessionState.JOINED) {
            this._curSession.sendObject(new Consistency(false));
        }
    };

    HybridSession.prototype._clearOwnOperation = function(r) {
        this._ownOperationPr = null;
        this._ownOperationParam = null;
        return async.exitFinally(r);
    };

    HybridSession.prototype._setOwnOperation = function(promise, opParam) {
        this._ownOperationPr = promise;
        this._ownOperationParam = opParam;
        var clear = this._clearOwnOperation.bind(this);
        promise.then(clear, clear).catch(logger.warn.bind(logger));
    };

    HybridSession.prototype._clearOwnProposal = function(r) {
        this._ownProposalPr = null;
        this._ownProposalPrev = null;
        this._ownProposalHash = null;
        return async.exitFinally(r);
    };

    HybridSession.prototype._setOwnProposal = function(prev, pHash) {
        var p = async.newPromiseAndWriters();
        this._ownProposalPr = p;
        this._ownProposalPrev = prev;
        this._ownProposalHash = pHash;
        var clear = this._clearOwnProposal.bind(this);
        p.promise.then(clear, clear).catch(logger.warn.bind(logger));
        return p.promise;
    };

    // Execute necessary book-keeping tasks

    HybridSession.prototype._maybeFinishOwnProposal = function(pHash, inPid, inPrevPid, greeting) {
        if (pHash === this._ownProposalHash) {
            _assert(this._ownProposalPrev === inPrevPid);
            this._ownProposalPr.resolve(greeting);
        } else if (this._ownProposalPrev === inPrevPid) {
            this._ownProposalPr.reject(new Error("ProposalRejected: " + btoa(inPid)));
        }
    };

    HybridSession.prototype._maybeSyncNew = function(members) {
        _assert(this._channel.curMembers() !== null);
        if (this._channel.curMembers().size === 1) {
            this._serverOrder.syncNew();
            this._channelJustSynced = true;
        }
        // if someone invites us to a channel, just wait for them to include us
        // TODO(xl): [F] (parallel-op) this may not be the best thing to do; need more data to decide
    };

    HybridSession.prototype._maybeHandleTasks = function() {
        this._assertConsistentTasks();

        if (this._ownOperationCb) {
            logger.info("ignored tasks due to ongoing own operation: " +
                this._ownOperationParam.slice());
        } else if (this._greeting) {
            logger.info("ignored tasks due to ongoing operation: " +
                this._greeting.getNextMembers().toArray());
        } else if (this._ownProposalPr) {
            logger.info("ignored tasks due to ongoing own proposal: " +
                btoa(this._ownProposalHash));
        } else {
            // taskLeave is handled in onPrevSessionFin
            if (this._taskExclude.size) {
                var to_exclude = ImmutableSet.from(this._taskExclude);
                var p = this._proposeGreetInit(ImmutableSet.EMPTY, to_exclude);
                p.catch(function(e) {
                    // TODO(xl): [D] maybe re-schedule
                    logger.info("proposal to exclude: " + to_exclude + " failed, hopefully not a problem");
                });
            }
            return;
        }

        // probably don't need to reschedule-after-ignore since there's enough
        // hooks elsewhere to do that already
        logger.info("remaining tasks: -" + ImmutableSet.from(this._taskExclude).toArray() +
            "; --" + ImmutableSet.from(this._taskLeave).toArray());
    };

    HybridSession.prototype._assertConsistentTasks = function() {
        _assert(struct.isDisjoint(this._taskExclude, this._taskLeave));
    };

    // Decide responses to others doing certain things

    // Respond to others that intend to leave the overall session.
    // This happens when someone sends two Consistency messages in a row,
    // to some sub-session.
    HybridSession.prototype._onMaybeLeaveIntent = function(sess, evt) {
        var msg = sess.transcript().get(evt.mId);
        if (!Consistency.isFin(msg.body) || msg.author === this._owner) {
            return;
        }
        if (msg.parents.size !== 1) {
            return;
        }
        var pmsg = sess.transcript().get(msg.parents.toArray()[0]);
        if (!Consistency.isFin(pmsg.body) || pmsg.author !== msg.author) {
            return;
        }
        if (this.curMembers().has(msg.author)) {
            this._taskExclude.add(msg.author);
            logger.info("added to taskExclude because they sent a leave-intent: " + msg.author);
            this._maybeHandleTasks();
        }
    };

    // Called when the previous session reaches consistency.
    // Leave the channel, or make others leave, depending on what is appropriate.
    HybridSession.prototype._onPrevSessionFin = function(sess) {
        if (!this._channel.curMembers()) {
            // already left channel, nothing to do
            return;
        } else if (sess !== this._prevSession) {
            logger.info("onPrevSessionFin called with obsolete session, ignoring");
            return;
        }

        // assume that we didn't start an operation to re-include these guys
        // in the meantime; this is forbidden by protocol anyways; we have to
        // kick users that were excluded, before they can be included, see
        // checks in _changeMembership for details
        var pendingLeave = this._channel.curMembers().intersect(this._taskLeave);
        if (pendingLeave.size) {
            this._channel.send({ leave: pendingLeave });
            logger.info("requested channel leave: " + pendingLeave.toArray());
        }

        // if we didn't leave the channel already, leave it
        if (this._curSession === null && this._serverOrder.isSynced()) {
            if (this._greeting === null) {
                this._channel.send({ leave: true });
                logger.info("requested channel leave self: " + this._owner);
            } else {
                // we/someone is already trying to re-include us
                // (we may or may not have left in the meantime)
                _assert(this._greeting.getNextMembers().has(this._owner));
            }
        }
    };

    HybridSession.prototype._onGreetingComplete = function(greeting) {
        _assert(greeting === this._greeting);
        var prevMembers = greeting.getPrevMembers();
        var newMembers = greeting.getNextMembers();
        var channelMembers = this._channel.curMembers();

        if (!newMembers.has(this._owner)) {
            // if we're being excluded, pretend nothing happened and just
            // wait for someone to kick us, as per msg-notes
            throw new Error("OperationIgnored: ignored completed greeting to exclude us");
        }

        if (greeting.metadataIsAuthenticated()) {
            this._serverOrder.setMetadataAuthenticated(greeting.getMetadata().prevPf);
        }

        var self = this;
        _assert(!newMembers.subtract(channelMembers).size,
            this._owner + "; " + btoa(this.sessionId()) +
            ": greeting completed when not all members were in the channel; " +
            prevMembers.toArray() + " -> " + newMembers.toArray() + " with " + channelMembers.toArray());

        var diff = prevMembers.diff(newMembers);
        var include = diff[0], exclude = diff[1];
        if (exclude.size) {
            exclude.forEach(this._taskExclude.delete.bind(this._taskExclude));
            var toLeave = channelMembers.intersect(exclude);
            if (toLeave.size) {
                logger.info("added to taskLeave because they were excluded from the session: " + toLeave.toArray());
                toLeave.forEach(this._taskLeave.add.bind(this._taskLeave));
            }
        }

        this._assertConsistentTasks();
        return greeting;
    };

    HybridSession.prototype._onOthersEnter = function(others) {
        this._assertConsistentTasks();
        _assert(!others.intersect(this._taskLeave).size);
        var selfOp = this._ownOperationParam;
        var opInc = (selfOp && selfOp.action === "m") ? selfOp.include : ImmutableSet.EMPTY;
        var taskExc = others.intersect(this._taskExclude);
        var unexpected = others.subtract(taskExc).subtract(opInc);
        if (opInc.size) {
            // _change_membership should already be handling this
        }
        if (taskExc.size) {
            // we still haven't excluded them cryptographically, and can't
            // allow them to rejoin until we've done this. auto-kick them ASAP.
            // some GKAs allow computation of subgroup keys, but in that case we
            // can model it as a 1-packet membership operation (we need >= 1
            // packet for the ServerOrder accept/reject mechanism) and avoid
            // this code path entirely.
            logger.info("automatically kicking: " + taskExc.toArray() +
                " because they were previously in the channel and we haven't excluded them yet");
            this._channel.send({ leave: taskExc });
        }
        if (unexpected.size) {
            // TODO(xl): [D] add a SessionNotice event for this
            logger.info("unexpected users entered the channel: " + unexpected.toArray() +
                "; maybe someone else is including them, or they want to be invited?");
        }
        this._assertConsistentTasks();
    };

    HybridSession.prototype._onOthersLeave = function(others) {
        this._assertConsistentTasks();
        // TODO(xl): [!] (parallel-op) if there is an ongoing operation and any
        // leavers are in greeting.new_members then abort the operation, with the
        // "pseudo packet id" definition as mentioned in msg-notes. still put them
        // in pending_exclude, though.
        others.forEach(this._taskLeave.delete.bind(this._taskLeave));
        var toExclude = this.curMembers().intersect(others);
        if (toExclude.size) {
            toExclude.forEach(this._taskExclude.add.bind(this._taskExclude));
            logger.info("added to taskExclude because they left the channel: " + toExclude.toArray());
            this._maybeHandleTasks();
        }
        this._assertConsistentTasks();
    };

    // Receive handlers

    HybridSession.prototype._recv = function(recv_in) {
        if (this._pendingGreetingPostProcess) {
            if (this._greeting) {
                // TODO(xl): [!] support *non-immediate* asynchronous completion of greeting,
                // This will be much more complex, since for correctness we must not process
                // certain packets until this is complete. The easy & safe option is to not
                // process *all* packets, but this has a UI cost and it is OK to process *some*,
                // just the logic for identifying these will be a bit annoying.
                logger.warn("processing remote packet before already-completed-greeting " +
                    "finished all local processing! some incorrect behaviour may result.");
            } else {
                logger.debug("clearing pending-greeting flag");
                this._pendingGreetingPostProcess = false;
            }
        }

        if ("pubtxt" in recv_in) {
            if (this._recvGreet(recv_in)) {
                return true;
            } else {
                return this._tryDecrypt.trial(recv_in);
            }
        } else {
            recv_in = channel.checkChannelControl(recv_in);
            var enter = recv_in.enter;
            var leave = recv_in.leave;

            if (leave === true) {
                this._clearChannelRecords();
                this._clearOwnOperation();
                this._clearOwnProposal();
                if (this._greeting) {
                    // TODO(xl): [F] (handle-error) should be done via a Greeting API
                    this._clearGreeting();
                }
                if (this._curSession) {
                    this._changeSubSession(null);
                }
            } else if (leave && leave.size) {
                this._onOthersLeave(leave);
            }

            if (enter === true) {
                this._maybeSyncNew(recv_in);
            } else if (enter && enter.size) {
                this._onOthersEnter(enter);
            }

            return true;
        }
    };

    HybridSession.prototype._recvGreet = function(recv_in) {
        var pubtxt = recv_in.pubtxt;
        var sender = recv_in.sender;
        var channelMembers = this._channel.curMembers();
        var makePacketId = this._serverOrder.makePacketId.bind(this._serverOrder,
            pubtxt, sender, channelMembers);
        var op = this._greeter.partialDecode(this.curMembers(), pubtxt, sender, makePacketId);
        var self = this;

        if (op !== null) {
            if (this._serverOrder.isSynced() &&
                op.metadata && !this.curMembers().has(op.metadata.author)) {
                logger.info("ignored GKA request from outside of group");
                return true;
            }

            var makePacketHash = utils.sha256.bind(null, pubtxt);

            var postAcceptInitial = function(pI, prev_pF) {
                // TODO: [F] (handle-error) this may return null or throw, if partialDecode is too lenient
                var greeting = self._greeter.decode(
                    self._curGreetState, self.curMembers(), pubtxt, sender, op.pId);
                self._setGreeting(greeting);
                self._maybeFinishOwnProposal(makePacketHash(), pI, prev_pF, greeting);
            };

            var postAcceptFinal = function(pF, prev_pI) {
                if (!op.isInitial()) {
                    // Don't run the hook if we're an initial+final packet. We only set
                    // ownProposalPr for non-initial final packets. Whenever it is set
                    // for initial+final packets, it was for the purpose of it being an
                    // initial packet. In other languages, ownProposalPr is already null
                    // when we get here (by postAcceptInitial running clearOwnProposal),
                    // so we don't need this condition; however JS Promises resolve
                    // after the current tick, so clearOwnProposal has not yet run, and
                    //  _maybeFinishOwnProposal complains that prevPi doesn't match.
                    self._maybeFinishOwnProposal(makePacketHash(), pF, prev_pI, self._greeting);
                }
            };

            if (this._serverOrder.tryOpPacket(
                    this._owner, op, channelMembers, postAcceptInitial, postAcceptFinal)) {
                _assert(this._greeting);
                // accepted greeting packet, deliver it and maybe complete the operation
                var r = this._greeting.recv(recv_in);
                _assert(r); // TODO: [F] (handle-error) this may be false, if partialDecode is too lenient
                this._greeting.getNextMembers().forEach(this._taskLeave.delete.bind(this._taskLeave));
                if (!this._serverOrder.hasOngoingOp()) {
                    // if this was a final packet, greeting should complete ASAP
                    this._pendingGreetingPostProcess = true;
                }
            }
            return true;
        } else if (this._serverOrder.isSynced() && this._serverOrder.hasOngoingOp()) {
            // middle packet of existing operation
            return this._greeting.recv(recv_in);
        } else {
            return false;
        }
    };

    HybridSession.prototype._tryDecryptTimeout = function(recv_in) {
        this._events.publish(new NotDecrypted(this.sId, recv_in.sender, recv_in.pubtxt.length));
        // TODO(xl): [D/R] maybe drop the packet too. though we already got maxsize
    };

    HybridSession.prototype._tryDecryptTry = function(_, recv_in) {
        return this._sessionRecv.publish(recv_in).some(Boolean);
    };

    HybridSession.prototype._changeSubSession = function(greeting) {
        // Rotate to a new sub session with a different membership.
        // If greeting is null, this means we left the channel and the session.
        _assert(greeting === null || !this._curSession ||
            this.curMembers().equals(greeting.getPrevMembers()));

        var ownSet = this._ownSet;
        this._channelJustSynced = false;
        if (greeting && greeting.getNextMembers().size === 1) {
            _assert(greeting.getNextMembers().equals(ownSet));
            greeting = null;
        }

        if (this._prevSession) {
            // this ought to be unnecessary, see python code for details
            this._prevSession.stop();
            this._prevSessionCancel();
            if (!this._prevSession.isConsistent()) {
                this._droppedInconsistentSession = true;
            }
        }

        // Rotate current session to previous
        this._prevSession = this._curSession;
        this._prevSessionCancel = this._curSessionCancel;
        this._prevGreetState = this._curGreetState;
        if (this._prevSession && this._prevSession.state() === SessionState.JOINED) {
            // this is the only place .fin() should be called, if we're not leaving
            // this is because .fin() places a contract that we're not supposed to send
            // further messages, but we can't possibly guarantee this before a greeting
            // completes.
            this._prevSession.fin();
            this._prevSession.onFin(this._onPrevSessionFin.bind(this, this._prevSession));
        }

        if (greeting) {
            var sessionCreated = this._makeSubSession(greeting);
            this._curSession = sessionCreated.session;
            this._curSessionCancel = sessionCreated.sessionCancel;
            this._curGreetState = sessionCreated.greetState;

        } else {
            this._curSession = null;
            this._curSessionCancel = null;
            this._curGreetState = null;

            this._prevSession.stop();
            this._prevSessionCancel();
        }

        logger.info("changed session: " + (this._prevSession ? this._prevSession.toString() : null) +
            " -> " + (this._curSession ? this._curSession.toString() : null));
        var oldMembers = this._prevSession ? this._prevSession.curMembers() : ownSet;
        var newMembers = greeting ? greeting.getNextMembers() : ownSet;
        var diff = oldMembers.diff(newMembers);
        this._events.publish(new SNMembers(newMembers.subtract(diff[0]), diff[0], diff[1]));

        return greeting;
    };

    HybridSession.prototype._makeSubSession = function(greeting) {
        var subSId = greeting.getResultSId();
        var greetState = greeting.getResultState();
        var members = greeting.getNextMembers();
        var msgSecurity = this._makeMessageSecurity(greetState);

        var sess = new SessionBase(this._context, subSId, members, msgSecurity);

        var cancels = [];
        cancels.push(this._sessionRecv.subscribe(sess.recv.bind(sess)));
        cancels.push(sess.onSend(this._channel.send.bind(this._channel)));
        cancels.push(sess.chainUserEventsTo(this, this._events));
        cancels.push(this._messages.bindSource(sess, sess.transcript()));
        cancels.push(sess.onEvent(MsgAccepted)(this._onMaybeLeaveIntent.bind(this, sess)));

        return {
            session: sess,
            sessionCancel: async.combinedCancel(cancels),
            greetState: greetState
        };
    };

    // implements Session

    /**
     * @inheritDoc
     */
    HybridSession.prototype.sessionId = function() {
        return this._sId;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.owner = function() {
        return this._owner;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.messages = function() {
        return this._messages;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.state = function() {
        return this._curSession ? this._curSession.state() : SessionState.PARTED;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.curMembers = function() {
        return this._curSession ? this._curSession.curMembers() : this._ownSet;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.isConsistent = function() {
        return (!this._droppedInconsistentSession &&
                (!this._prevSession || this._prevSession.isConsistent()) &&
                (!this._curSession || this._curSession.isConsistent()));
    };

    HybridSession.prototype._proposeGreetInit = function(include, exclude) {
        _assert(!this._ownProposalHash);
        _assert(!include.intersect(this._taskLeave).size);
        _assert(!include.intersect(this._taskExclude).size);

        if (!this._serverOrder.isSynced()) {
            throw new Error("proposal not appropriate now: need to wait for someone to include you");
        }

        var curMembers = this.curMembers();
        var newMembers = curMembers.patch([include, exclude]);
        _assert(!curMembers.equals(newMembers));

        // concurrency resolution requires that everyone is in the channel when the server
        // echoes back the proposal, which is not exactly the same as when we send it.
        // but check this here anyway, to discourage unlikely-to-succeed workflows.
        var needToJoin = newMembers.subtract(this._channel.curMembers());
        if (needToJoin.size) {
            throw new Error("proposal not appropriate now: not in channel: " + needToJoin.toArray());
        }

        var prevPf = this._serverOrder.prevPf();
        var prevCh = this._serverOrder.prevCh();

        var parents = this._curSession ? this._curSession.transcript().max() : ImmutableSet.EMPTY;
        var pubtxt = this._greeter.encode(this._curGreetState, curMembers, newMembers,
            GreetingMetadata.create(prevPf, prevCh, this._owner, parents));
        var pHash = utils.sha256(pubtxt);

        var p = this._setOwnProposal(prevPf, pHash);
        logger.info("proposed new greeting pHash:" + btoa(pHash) +
            ": +{" + include.toArray() + "} -{" + exclude.toArray() + "}");
        this._channel.send({ pubtxt: pubtxt, recipients: curMembers.union(include) });
        return p;
    };

    /* Here follow implementations of "actions" to be executed. We try to
     * follow these general "async" action-flow principles:
     *
     * Checks on *arguments*, e.g. for include/exclude, should go in send()
     * rather than the private functions.
     *
     * Checks on state *preconditions* go in the private implementation methods
     * (_changeMembership, _includeSelf, _excludeSelf) and throw an Error if not
     * met. If it would be a no-op, we return an already-completed Deferred.
     *
     * The primary purpose of these actions are to change the *session*; channel
     * membership is secondary, and the operation (represented by the returned
     * Deferred) should not wait for channel operations that occur after the
     * *session* change completes. (OTOH, channel operation *preconditions* e.g.
     * entering the channel before a membership operation, must be waited upon,
     * of course.)
     *
     * TODO(xl): [D] (timeout-op) fail these operations after a timeout and/or
     * retry sub-operations if their failures are probably transitive
     */

    HybridSession.prototype._changeMembership = function(include, exclude) {
        // Expected post-state is:
        // COS_ || COsj (-> cos by onPrevSessionFin, after promise resolves)
        var state = this._internalState();
        if (state === "cos_") {
            throw new Error("not in channel yet; try { join: true } first");
        } else if (state === "COsj" || state === "Cos_") {
            throw new Error("already in the middle of joining or parting");
        } else {
            _assert(state === "COS_" || state === "COsJ");
        }

        var self = this;
        var p = async.newPromiseAndWriters();

        if (include.intersect(this._taskLeave).size || include.intersect(this._taskExclude).size) {
            // members ignore being excluded until we kick them from the channel. so
            // we can't reinclude them until we have done so; otherwise they don't
            // clear their own cryptographic state.
            throw new Error("cannot include someone that we must (by protocol) exclude/leave first");
        }

        var p1;
        if (include.size) {
            p1 = this._channel.execute({ enter: include });
        } else {
            p1 = Promise.resolve(true);
        }
        p1.then(
            this._proposeGreetInit.bind(this, include, exclude)
        ).catch(p.reject);

        // TODO(xl): [D] this could be resolved more intelligently, e.g. with PromisingSet
        this._events.subscribe(SNMembers).untilTrue(function(evt) {
            if (evt.include.equals(include) && evt.exclude.equals(exclude)) {
                p.resolve(self);
                return true;
            }
        });
        return p.promise;
    };

    HybridSession.prototype._includeSelf = function() {
        // Expected post-state is:
        // COS_ || COsJ
        var state = this._internalState();
        if (state === "COS_" || state === "CosJ") {
            return Promise.resolve(this);
        } else if (state === "COsj" || state === "Cos_") {
            throw new Error("already in the middle of joining or parting");
        } else {
            _assert(state === "cos_");
        }

        var self = this;
        var p = async.newPromiseAndWriters();

        var p1;
        if (this._channel.curMembers()) {
            p1 = Promise.resolve(this._channel.curMembers());
        } else {
            p1 = this._channel.execute({ enter: true });
        }
        p1.then(function() {
            var curMembers = self._channel.curMembers();
            if (curMembers && curMembers.size > 1) {
                // if it's not empty, wait for someone to invite us
                self._events.subscribe(SNMembers).untilTrue(function(evt) {
                    if (evt.remain.equals(self._ownSet) && evt.include.size) {
                        p.resolve(self);
                        return true;
                    }
                });
            } else {
                // maybeSyncNew should have been called by this stage
                _assert(self._serverOrder.isSynced());
                // no session membership change, just finish this operation.
                p.resolve(self);
            }
        }).catch(p.reject);

        return p.promise;
    };

    HybridSession.prototype._excludeSelf = function() {
        // Expected post-state is:
        // cos_ || COsj (-> cos by onPrevSessionFin, after promise resolves)
        // Here, we are a bit more lenient than the other actions; it should
        // always be possible to part the session, and have the internal state
        // remain consistent and be able to continue further from this.
        var state = this._internalState();
        if (state === "cos_") {
            return Promise.resolve(this);
        } else if (state === "Cos_" || state === "COsJ" || state === "COsj" && this._greeting) {
            // no session and no local automated process, just leave the channel
            return this._channel.execute({ leave: true });
        } else if (state === "COsj" && !this._greeting) {
            // TODO(xl): [F] (parallel-op) might be able to speed things up a bit...
            throw new Error("already in the middle of parting");
        } else {
            _assert(state === "COS_");
        }

        var self = this;
        var p = async.newPromiseAndWriters();

        // send leave-intent, i.e. double-fin. this tells others that we want to leave
        // the whole HybridSession, as opposed to just the child Session.
        this._curSession.sendObject(new Consistency(true));
        this._curSession.fin();
        // try to reach consistency, then leave the channel
        this._curSession.onFin(function(mId) {
            if (self._channel.curMembers()) {
                self._channel.send({ leave: true });
            }
        });

        this._events.subscribe(SNMembers).untilTrue(function(evt) {
            if (evt.remain.equals(self._ownSet) && evt.exclude.size) {
                p.resolve(self);
                return true;
            }
        });
        return p.promise;
    };

    HybridSession.prototype._runOwnOperation = function(opParam, run) {
        if (!this._ownOperationCb) {
            var p = run();
            this._setOwnOperation(p, opParam);
            return p;

        } else if (this._ownOperationParam.equals(opParam)) {
            return this._ownOperationCb;
        } else {
            throw new Error("OperationInProgress: " + this._ownOperationParam);
        }
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.send = function(action) {
        if ("contents" in action) {
            return this._curSession ? this._curSession.sendData(action.contents) : false;
        } else {
            return this.execute(action) !== null;
        }
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.execute = function(action) {
        action = session.checkSessionAction(action);

        if ("contents" in action) {
            throw new Error("not implemented");

        } else if ("include" in action || "exclude" in action) {
            var include = action.include;
            var exclude = action.exclude;
            if (include.has(this._owner) || exclude.has(this._owner)) {
                throw new Error("cannot include/exclude yourself");
            }
            return this._runOwnOperation(new OwnOp("m", include, exclude),
                this._changeMembership.bind(this, include, exclude));

        } else if ("join" in action && !this._curSession) {
            return this._runOwnOperation(new OwnOp("j"), this._includeSelf.bind(this));

        } else if ("part" in action && this._curSession) {
            return this._runOwnOperation(new OwnOp("p"), this._excludeSelf.bind(this));

        } else {
            return Promise.resolve(true);
        }
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.onRecv = function(sub) {
        // subscribe the given subscriber to all events
        var evtctx = this._events;
        return async.combinedCancel(
            evtctx.evtcls().toArray().map(function(ec) {
                return evtctx.subscribe(ec)(sub);
            }));
    };


    ns.HybridSession = HybridSession;

    return ns;
});
