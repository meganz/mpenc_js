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
    "mpenc/impl/channel",
    "mpenc/impl/liveness",
    "mpenc/impl/transcript",
    "mpenc/helper/assert",
    "mpenc/helper/struct",
    "mpenc/helper/async",
    "mpenc/helper/utils",
    "promise-polyfill",
    "megalogger"
], function(session, channel, greeter, liveness, message,
    channelImpl, livenessImpl, transcriptImpl,
    assert, struct, async, utils, Promise, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/impl/session
     * @private
     * @description
     * Session related operations
     */
    var ns = {};

    var logger = MegaLogger.getLogger("session", undefined, "mpenc");
    var _assert = assert.assert;

    // import events
    var MsgAccepted   = session.MsgAccepted;
    var MsgFullyAcked = session.MsgFullyAcked;
    var MsgReady      = session.MsgReady;
    var NotAccepted   = session.NotAccepted;
    var NotFullyAcked = session.NotFullyAcked;
    var SNState = session.SNState;
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
     * @private
     * @memberOf module:mpenc/impl/session
     */
    var SessionContext = struct.createTupleClass("SessionContext",
        "owner keepfresh timer privKey pubKey pubKeyDir flowctl codec makeMessageLog");

    Object.freeze(SessionContext.prototype);
    ns.SessionContext = SessionContext;


    /**
     * Ratio of heartbeat interval to the full-ack-interval
     * How long to wait when we are idle, before sending a heartbeat.
     */
    var HEARTBEAT_RATIO = 4;

    /**
     * Ratio of fin consistency timeout to the broadcast-latency
     * How long to wait for consistency, before we publish that fin() completed with inconsistency.
     */
    var FIN_TIMEOUT_RATIO = 16;

    /**
     * Ratio of fin consistency grace-wait to the broadcast-latency
     * How long to wait after consistency is reached, before we publish that fin() completed with consistency.
     */
    var FIN_CONSISTENT_RATIO = 1;

    /**
     * Give others a little bit longer than ourselves to expire freshness.
     */
    var EXPIRE_GRACE_RATIO = 1.0625;

    /**
     * Ratio of wait-period to (expected GKA run time + broadcast+latency).
     * The wait-period is the average time we wait before trying to re-enter
     * the channel, if we're auto-kicked when trying to join a session.
     */
    var REENTER_GRACE_RATIO = 1.5;

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
     * @private
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
        this._stateMachine = new StateMachine(SNState, SessionState.JOINED);
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
        this._tryAccept = new TrialBuffer('try-accept for ' + this.toString(true), tryAccept);

        this._fin = new Observable();
        this._pubtxt = new Map(); /* ciphertxt cache, mId->pubtxt and pubtxt->mId*/

        this._cancels = async.combinedCancel(cancels);
    };

    SessionBase.EventTypes = [SNState, MsgAccepted, MsgFullyAcked, NotAccepted, NotFullyAcked];

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
    SessionBase.prototype.toString = function(short) {
        return this._owner + ":" + btoa(this._sId.substring(0, 3)) +
            (short ? "" : ":[" + this.curMembers().toArray() + "]");
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
     * @param content {?string}
     * @returns {boolean} Whether the content were accepted to be sent.
     */
    SessionBase.prototype.sendData = function(content) {
        // TODO(xl): [F] if we "recently" (e.g. <1s ago) accepted a message, the
        // user is unlikely to have fully-understood it. so perhaps we should
        // actually only point to non-recent messages as the "parent" messages.
        return this.sendObject((content) ? new Payload(content) : new ExplicitAck(true));
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

        var enc = this._msgsec.authEncrypt(ts, {
            author: author,
            parents: parents,
            recipients: recipients,
            body: this._codec.encode(body),
        });
        var pubtxt = enc.pubtxt, secret = enc.secrets;

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
            var message = dec.message, secret = dec.secrets;
            mId = secret.mId;
        } catch (e) {
            logger.debug("SessionBase.recv rejected packet: " + e);
            return false;
        }
        _assert(message.author !== this.owner(), 'received non-duplicate message from self: ' + btoa(mId));

        try {
            var body = this._codec.decode(message.body);
        } catch (e) {
            secret.destroy();
            this._handleInvalidMessage(mId, message.author, message.parents, message.recipients, e);
            return true; // decrypt succeeded so message was indeed properly part of the session
        }

        var msg = new Message(mId, message.author, message.parents, message.recipients, body);
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
        var finTimeout = this._broadcastLatency(FIN_TIMEOUT_RATIO);
        var finConsistent = this._broadcastLatency(FIN_CONSISTENT_RATIO);
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
        var expireAfter = this._fullAckInterval(mId, HEARTBEAT_RATIO);
        presence.renew(uId, knownTs,
                       own ? expireAfter : expireAfter * EXPIRE_GRACE_RATIO);
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
        return this._fullAckInterval(this.lastOwnMsg(), HEARTBEAT_RATIO);
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


    var OwnOp = struct.createTupleClass("OwnOp", "action include exclude");

    /**
     * A Session with a linear order on its membership operations.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/session
     * @implements {module:mpenc/session.Session}
     * @param context {module:mpenc/impl/session.SessionContext} Session context.
     * @param sId {string} Session id, shared between all members.
     * @param channel {module:mpenc/channel.GroupChannel} Group transport channel.
     * @param greeter {module:mpenc/greet/greeter.Greeter} Membership operation component.
     * @param makeMessageSecurity {function} 1-arg factory function, that takes
     *      a {@link module:mpenc/greet/greeter.GreetStore} and creates a new
     *      {@link module:mpenc/message.MessageSecurity}.
     * @param [options] {Object} Tweak some behaviours; see below. Note that
     *      non-default values are, in some sense, "less safe" than the default
     *      values; please be aware of this and don't surprise your users.
     * @param [options.autoIncludeExtra] {boolean} Whether to automatically include
     *      new members that enter the transport channel. Default: false.
     * @param [options.stayIfLastMember] {boolean} Whether to remain in the channel
     *      instead of leaving it, as the last member. Default: false.
     */
    var HybridSession = function(context, sId, channel,
        greeter, makeMessageSecurity, options) {
        options = options || {};
        this._context = context;
        this._events = new EventContext(Session.EventTypes);
        this._autoIncludeExtra = options.autoIncludeExtra || false;
        this._stayIfLastMember = options.stayIfLastMember || false;
        this._fubar = false;

        this._owner = context.owner;
        this._ownSet = new ImmutableSet([this._owner]);
        this._sId = sId;
        this._channel = channel;

        this._timer = context.timer;
        var cancels = [];
        var self = this;

        this._flowctl = context.flowctl;

        var messageLog = context.makeMessageLog();
        cancels.push(messageLog.onUpdate(function(update) {
            self._events.publish(MsgReady.fromMessageLogUpdate(messageLog, update));
        }));
        this._messages = messageLog;

        this._greeter = greeter;
        this._makeMessageSecurity = makeMessageSecurity;

        // sub-sessions
        this._current = null;
        this._previous = null;
        this._droppedInconsistentSession = false;

        // sub-session send/recv logic
        cancels.push(this._channel.onRecv(this._recv.bind(this)));
        this._sessionRecv = new Observable(); // for sub-sessions to listen on; filters out greeter/control packets
        var tryDecrypt = new TrialTimeoutTarget(
            this._timer, this._flowctl.getBroadcastLatency(),
            this._tryDecryptTimeout.bind(this),
            {
                maxSize: this._flowctl.asynchronity.bind(this._flowctl, this),
                paramId: function(recv_in) {
                    return "ccId" in recv_in ? String(recv_in.ccId) : utils.sha256(recv_in.pubtxt);
                },
                tryMe: this._tryDecryptTry.bind(this)
            });
        this._tryDecrypt = new TrialBuffer('try-decrypt for ' + this.toString(true), tryDecrypt);
        this._ccId = 0;

        // global ops
        this._serverOrder = new ServerOrder();
        this._greetingCancel = function() {};
        this._clearChannelRecords();
        this._clearGreeting();

        // own ops
        this._clearOwnProposal();
        this._clearOwnOperation();

        this._cancel = async.combinedCancel(cancels);
    };

    /**
     * @returns {string} A short summary of this session.
     */
    HybridSession.prototype.toString = function(short) {
        return this._owner + ":" + btoa(this._sId.substring(0, 3)) +
            (short ? "" : ":" + this.state() + ":" + this._internalState() + ":[" + this.curMembers().toArray() + "]");
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
            _assert(!this._current);
            //_assert(!this._greeting); // fails because _clearGreeting is called asynchronously >:[
            // Not in the channel. Stable.
            return "cos_";
        } else if (!this._serverOrder.isSynced()) {
            _assert(!this._current);
            _assert(!this._greeting);
            // In the channel, ServerOrder unsynced. Unstable; others should
            // cause us to be synced later, expecting COsj.
            return "Cos_";
        } else if (!this._current) {
            // In the channel, ServerOrder synced, but no session.
            if (this._channelJustSynced) {
                _assert(!this._greeting);
                // Stable; we just entered the channel and we're the only ones here.
                return "COsJ";
            } else {
                // Unstable; one of:
                // - (greeting !== null): we entered the channel, and just
                //   accepted a greeting, but it's not yet complete -> COS_
                // - (greeting === null): we just completed a _changeMembership
                //   that implicitly excluded everyone else, but we haven't yet
                //   left the channel, so as to wait for consistency -> cos_
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
        // Members already present when we entered, that have not yet left.
        this._moreSeniorThanUs = new Set();
        /* Members we'll try to exclude from the session. We add someone when:
         *
         * - they send a leave-intent (2x Consistency(close=true) messages)
         * - they leave the channel (e.g. are disconnected)
         *
         * By protocol, users in this set are prevented from re-entering the
         * channel [rule EAL] until the exclude operation completes. */
        this._taskExclude = new Set();
        /* Members we'll try to kick from the channel. We add someone when:
         *
         * - a greeting to exclude them from the session completes, but they
         *   haven't left the channel yet.
         *
         * By protocol, users in this set are prevented from being re-included
         * into the session [rule IAL], until they've left. */
        this._taskLeave = new Set();
        return async.exitFinally(r);
    };

    HybridSession.prototype._clearGreeting = function(r) {
        this._greetingCancel();
        this._greetingCancel = null;
        this._greeting = null;
        this._pendingGreetPP = false;
        this._tryDecrypt.retryAll();
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
        // it would be cleaner to chain a bunch of then()s here; but unfortunately
        // JS promises resolve in the next tick, which means clear() would run too
        // late and break some other stuff that depends on it
        p.then(function(greeting) {
            try {
                return self._changeSubSession(self._onGreetingComplete(greeting));
            } finally {
                clear();
            }
        }, clear).catch(logger.warn.bind(logger));
        // greeting accepted, try to achieve consistency in case this succeeds
        // and we need to rotate the sub-session
        if (this._current && this._current.sess.state() === SessionState.JOINED) {
            this._current.sess.sendObject(new Consistency(false));
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
            this._ownProposalPr.reject(new Error("ProposalRejected: " +
                btoa(this._ownProposalHash) + " (pHash) by accepted " + btoa(inPid)));
        }
    };

    HybridSession.prototype._maybeSyncNew = function() {
        var channelMembers = this._channel.curMembers();
        _assert(channelMembers !== null);
        _assert(!this._serverOrder.isSynced());
        if (this._moreSeniorThanUs.size) {
            // Members more senior than us are still in the channel. Assume that they
            // have an exising session so wait for them to include us. If this isn't
            // true, hopefully they will eventually leave and trigger the below path.
            return;
        }
        // All seniors have left but we're still not synced, so take responsibility
        // for creating a new session and including the less senior members.
        this._serverOrder.syncNew();
        this._channelJustSynced = true;
        if (channelMembers.size > 1) {
            var others = channelMembers.subtract(this._ownSet);
            this._maybeHandleExtra("extra channel users after syncing serverOrder", others);
        }
    };

    HybridSession.prototype._maybeHandleExtra = function(preamble, extras) {
        if (this._autoIncludeExtra) {
            logger.info(preamble + ": " + extras.toArray() +
                "; auto-include them as per autoIncludeExtra=true");
            this._proposeGreetInit(extras, ImmutableSet.EMPTY);
        } else {
            // TODO(xl): distinguish "X entered themselves" vs "Y made X enter"
            // and use this to implement UI notifications as per [rule ES]
            logger.info(preamble + ": " + extras.toArray() +
                "; ignored, assuming that someone else is responsible for them");
        }
    };

    HybridSession.prototype._maybeHandleTasks = function() {
        this._assertConsistentTasks(true);

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
                var toExclude = ImmutableSet.from(this._taskExclude);
                var p = this._proposeGreetInit(ImmutableSet.EMPTY, toExclude);
                p.catch(function(e) {
                    // TODO(xl): [D] maybe re-schedule
                    logger.info("proposal to exclude: " + toExclude.toArray() + " failed, hopefully not a problem");
                });
            }
            return;
        }

        // probably don't need to reschedule-after-ignore since there's enough
        // hooks elsewhere to do that already
        logger.info("remaining tasks: -" + ImmutableSet.from(this._taskExclude).toArray() +
            "; --" + ImmutableSet.from(this._taskLeave).toArray());
    };

    HybridSession.prototype._assertConsistentTasks = function(checkAgainstCurrentState) {
        if (checkAgainstCurrentState) {
            _assert(!ImmutableSet.from(this._taskExclude).subtract(this.curMembers()).size);
            _assert(!ImmutableSet.from(this._taskLeave).subtract(this._channel.curMembers()).size);
        }
        _assert(struct.isDisjoint(this._taskExclude, this._taskLeave));
    };

    HybridSession.prototype._maybeLeaveChannel = function(pendingLeave) {
        pendingLeave = pendingLeave || ImmutableSet.EMPTY;
        if (this._stayIfLastMember &&
            this._channel.curMembers().subtract(pendingLeave).equals(this._ownSet)) {
            logger.info("remaining in channel as the last member: " + this._owner);
            _assert(!this._greeting);
            this._clearOwnOperation();
            this._clearOwnProposal();
            if (this._current) {
                this._changeSubSession(null);
            }
            this._channelJustSynced = true;
            return Promise.resolve(this);
        } else {
            logger.info("requesting channel leave self: " + this._owner);
            return this._channel.execute({ leave: true });
        }
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
        } else if (!this._previous || sess !== this._previous.sess) {
            logger.info("onPrevSessionFin called with obsolete session, ignoring");
            return;
        }

        // assume that we didn't start an operation to re-include these guys
        // in the meantime; this is forbidden by protocol anyways; we have to
        // kick users that were excluded, before they can be included, see
        // checks in _changeMembership for details
        var pendingLeave = this._channel.curMembers().intersect(this._taskLeave);
        if (pendingLeave.size) {
            logger.info("requesting channel leave: " + pendingLeave.toArray());
            this._channel.send({ leave: pendingLeave });
        }

        // if we didn't leave the channel already, leave it
        if (!this._current && this._serverOrder.isSynced()) {
            if (!this._greeting) {
                this._maybeLeaveChannel(pendingLeave);
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
        // we use _pendingGreetPP to store this._channel.curMembers() back from when
        // the greeting actually completed, because this._channel isn't protected by the
        // post-processing delaying logic in this class, and may have advanced too much
        var channelMembers = this._pendingGreetPP;

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
        _assert(!others.intersect(this._taskLeave).size,
            "somehow taskLeave was set for absent user: " + this._taskLeave);
        var selfOp = this._ownOperationParam;
        var opInc = (selfOp && selfOp.action === "m") ? selfOp.include : ImmutableSet.EMPTY;
        var taskExc = others.intersect(this._taskExclude);
        var unexpected = others.subtract(taskExc).subtract(opInc);
        if (opInc.size) {
            // _change_membership should already be handling this
        }
        if (taskExc.size) {
            // [rule EAL] we still haven't excluded them cryptographically, and can't
            // allow them to reenter until we've done this; auto-kick them ASAP. some
            // GKAs allow computation of subgroup keys, but in that case we can model
            // it as a 1-packet membership operation (we need >= 1 packet for the
            // accept/reject mechanism anyways) and avoid this code path entirely.
            logger.info("automatically kicking: " + taskExc.toArray() +
                " because they were previously in the channel and we haven't excluded them yet");
            this._channel.send({ leave: taskExc });
        }
        if (unexpected.size) {
            if (this._greeting) {
                // [rule EO]
                _assert(!unexpected.intersect(this._greeting.getNextMembers()).size);
                logger.info("automatically kicking: " + unexpected.toArray() +
                    " because a greeting is in progress");
                this._channel.send({ leave: unexpected });
            } else {
                // [rule ES]
                this._maybeHandleExtra("unexpected users entered the channel", unexpected);
            }
        }
        this._assertConsistentTasks(true);
    };

    HybridSession.prototype._onOthersLeave = function(others) {
        this._assertConsistentTasks();
        // if others left and we're still not synced, try to sync again
        others.forEach(this._moreSeniorThanUs.delete.bind(this._moreSeniorThanUs));
        if (!this._serverOrder.isSynced()) {
            this._maybeSyncNew();
        }
        if (this._greeting && this._greeting.getNextMembers().intersect(others).size) {
            // [rule LOI] if there is an ongoing operation, and anyone from it leaves, then
            // abort it, with the "pseudo packet id" definition as mentioned in msg-notes.
            _assert(this.curMembers().equals(this._greeting.getPrevMembers()));
            this._serverOrder.acceptLeavePacket(others, this._channel.curMembers(), this.curMembers());
            this._greeting.fail(new Error("OperationAborted: others left the channel: " + others.toArray()));
        }
        others.forEach(this._taskLeave.delete.bind(this._taskLeave));
        var toExclude = this.curMembers().intersect(others);
        if (toExclude.size) {
            // [rule LS, LOX]
            toExclude.forEach(this._taskExclude.add.bind(this._taskExclude));
            logger.info("added to taskExclude because they left the channel: " + toExclude.toArray());
            this._maybeHandleTasks();
        }
        this._assertConsistentTasks(true);
    };

    // Receive handlers

    HybridSession.prototype._recv = function(recv_in) {
        if (this._pendingGreetPP) {
            if (!("pubtxt" in recv_in)) {
                // Tag the packet with a unique channel-control-id so trialBuffer can identify it.
                // We don't attempt to deduplicate these messages; server is supposed to be well-behaved.
                // We'll detect any misbehaviour later via the TODO ServerOrder consistency checks.
                recv_in.ccId = this._ccId++;
            }
            // TrialBuffer should not re-order greeter/control packets
            return this._tryDecrypt.trial(recv_in, true);
        } else {
            return this._recvMain(recv_in, true);
        }
    };

    HybridSession.prototype._recvMain = function(recv_in, useQueue) {
        try {
            if ("pubtxt" in recv_in) {
                if (this._recvGreet(recv_in)) {
                    return true;
                } else if (useQueue) {
                    return this._tryDecrypt.trial(recv_in);
                } else {
                    return this._sessionRecv.publish(recv_in).some(Boolean);
                }
            } else {
                recv_in = channel.checkChannelControl(recv_in);
                var enter = recv_in.enter;
                var leave = recv_in.leave;

                if (leave === true) {
                    // [rule LI]
                    this._clearChannelRecords();
                    this._clearOwnOperation();
                    this._clearOwnProposal();
                    if (this._greeting) {
                        if (this._greeting.getNextMembers().has(this._owner)) {
                            this._greeting.fail(new Error("OperationAborted: we left the channel"));
                        } else {
                            this._greeting.fail(new Error("OperationIgnored: we left the channel "
                                + "during a greeting to exclude us; assuming it succeeded"));
                        }
                    }
                    if (this._current) {
                        this._changeSubSession(null);
                    }
                } else if (leave && leave.size) {
                    this._onOthersLeave(leave);
                }

                if (enter === true) {
                    this._moreSeniorThanUs = this._channel.curMembers().subtract(this._ownSet).asMutable();
                    this._maybeSyncNew();
                } else if (enter && enter.size) {
                    this._onOthersEnter(enter);
                }

                return true;
            }
        } catch (e) {
            this._fubar = true;
            throw e;
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
                // message may be confusing; sometimes this happens when we are at COsJ
                // by a rejected proposal to include us; the proposal already accepted
                // of course is *also* outside of "our current group".
                logger.info("ignored GKA request from outside of group " + this.toString()
                    + " by: " + op.metadata.author);
                return true;
            }

            var makePacketHash = utils.sha256.bind(null, pubtxt);

            var postAcceptInitial = function(pI, prev_pF) {
                // TODO: [F] (handle-error) this may return null or throw, if partialDecode is too lenient
                var oldState = self._current ? self._current.greetState : null;
                var greeting = self._greeter.decode(oldState, self.curMembers(), pubtxt, sender, op.pId);
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
                if (op.isInitial() && this._taskLeave.size) {
                    // [rule IAL] Members haven't left the channel after being excluded, but
                    // someone is trying to re-include them. This is against protocol and
                    // probably won't end well, so kick them now. If not a final packet,
                    // kicking will make the greeting fail; if final, onOthersLeave will
                    // set them to be automatically excluded again.
                    var toLeave = ImmutableSet.from(this._taskLeave).intersect(this._greeting.getNextMembers());
                    if (toLeave.size) {
                        logger.info("automatically kicking: " + toLeave.toArray() +
                            " because they were excluded from the session and we haven't kicked them yet");
                        this._channel.send({ leave: toLeave });
                    }
                }
                if (op.isFinal()) {
                    _assert(!this._serverOrder.hasOngoingOp());
                    // wait for greeting to complete before processing other packets
                    this._pendingGreetPP = this._channel.curMembers();
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
        // in unit tests, this sometimes throws a harmless stack trace due to
        // recv_in actually being a ChannelControl packet; in real code this
        // probably won't happen because the timeout should be set to a much
        // higher value than it takes for greeting post-processing to complete.
        this._events.publish(new NotDecrypted(this._sId, recv_in.sender, recv_in.pubtxt.length));
        // TODO(xl): [D/R] maybe drop the packet too. though we already got maxsize
    };

    HybridSession.prototype._tryDecryptTry = function(pending, recv_in) {
        // control flow paths this can be called under:
        // [1] pendingGreetPP==T: recv() -> tryDecrypt.trial()
        // [2] pendingGreetPP==F: recv() -> recvMain(_, true) -> tryDecrypt.trial()
        // [3] pendingGreetPP==F: clearGreeting() -> tryDecrypt.retryAll()
        if (this._pendingGreetPP) {
            // [1] if we're waiting for a completed greeting to finish post-processing,
            // then only process session packets, which don't interfere with that.
            if ("pubtxt" in recv_in) {
                return this._sessionRecv.publish(recv_in).some(Boolean);
            } else {
                return false;
            }
        } else if (pending) {
            // [2, 3] we might be acting on queued greeter/control packets.
            // for [2] this is inefficient (but correct). we should do else{}
            // instead, but detecting that would add too much complexity
            return this._recvMain(recv_in, false);
        } else {
            // [2] only session packets should reach this code path
            _assert("pubtxt" in recv_in);
            return this._sessionRecv.publish(recv_in).some(Boolean);
        }
    };

    HybridSession.prototype._changeSubSession = function(greeting) {
        // Rotate to a new sub session with a different membership.
        // If greeting is null, this means we left the channel and the session.
        _assert(!greeting || !this._current ||
            this.curMembers().equals(greeting.getPrevMembers()));

        var ownSet = this._ownSet;
        this._channelJustSynced = false;
        if (greeting && greeting.getNextMembers().size === 1) {
            _assert(greeting.getNextMembers().equals(ownSet));
            greeting = null;
        }

        if (this._previous) {
            // this ought to be unnecessary, see python code for details
            this._previous.sess.stop();
            this._previous.cancel();
            if (!this._previous.sess.isConsistent()) {
                this._droppedInconsistentSession = true;
            }
        }

        // Rotate current session to previous
        this._previous = this._current;
        if (this._previous && this._previous.sess.state() === SessionState.JOINED) {
            // this is the only place .fin() should be called, if we're not leaving
            // this is because .fin() places a contract that we're not supposed to send
            // further messages, but we can't possibly guarantee this before a greeting
            // completes.
            this._previous.sess.fin();
            this._previous.sess.onFin(this._onPrevSessionFin.bind(this, this._previous.sess));
        }

        if (greeting) {
            var sessionCreated = this._makeSubSession(greeting, this._previous);
            this._current = sessionCreated;

        } else {
            this._current = null;

            this._previous.sess.stop();
            this._previous.cancel();
        }

        logger.info("changed session: " + (this._previous ? this._previous.sess.toString() : null) +
            " -> " + (this._current ? this._current.sess.toString() : null));
        var oldMembers = this._previous ? this._previous.sess.curMembers() : ownSet;
        var newMembers = greeting ? greeting.getNextMembers() : ownSet;
        var parents = this._current ? this._current.parents : ImmutableSet.EMPTY;
        var diff = oldMembers.diff(newMembers);
        this._events.publish(new SNMembers(newMembers.subtract(diff[0]), diff[0], diff[1], parents));

        return greeting;
    };

    HybridSession.prototype._makeSubSession = function(greeting, previous) {
        var subSId = greeting.getResultSId();
        var greetState = greeting.getResultState();
        var members = greeting.getNextMembers();
        var msgSecurity = this._makeMessageSecurity(greetState);

        var sess = new SessionBase(this._context, subSId, members, msgSecurity);

        var cancels = [];
        cancels.push(this._sessionRecv.subscribe(sess.recv.bind(sess)));
        cancels.push(sess.onSend(this._channel.send.bind(this._channel)));
        cancels.push(sess.chainUserEventsTo(this, this._events));
        cancels.push(sess.onEvent(MsgAccepted)(this._onMaybeLeaveIntent.bind(this, sess)));

        // TODO(xl): (server-consistency) check greeting.metadataIsAuthenticated === true here
        // and arrange for retroactive authentication if not...
        var parents = greeting.getMetadata().parents;
        var inPrevSession = function(mId) { return previous.sess.transcript().has(mId); };
        if (parents.size && previous && !(parents.toArray().every(inPrevSession))) {
            // it is possible but more complex to handle this case; assume servers are nice for now
            this._fubar = true;
            throw new Error("SNMember parents not all accepted; dodgy transport? "
                + parents.toArray().map(btoa));
        }

        // publish MsgAccepted events into our MessageLog
        var msgAcceptedSubscriber = this._messages.getSubscriberFor(sess.transcript(), new Map(previous ? [
            [parents, previous.sess.transcript()]
        ] : []));
        cancels.push(sess.onEvent(MsgAccepted)(function(evt) {
            return msgAcceptedSubscriber(evt.mId);
        }));

        return {
            sess: sess,
            cancel: async.combinedCancel(cancels),
            greetState: greetState,
            parents: parents,
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
        var state = this._internalState();
        var greeting = this._greeting;
        if (state === "COS_") {
            return SessionState.JOINED;
        } else if (state === "COsJ") {
            return greeting && !greeting.getNextMembers().has(this._owner)
                ? SessionState.PARTING : SessionState.JOINING;
        } else if (state === "COsj") {
            return greeting ? SessionState.JOINING : SessionState.PARTING;
        } else if (state === "Cos_") {
            return SessionState.JOINING;
        } else if (state === "cos_") {
            return SessionState.PARTED;
        } else {
            _assert(false);
        }
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.curMembers = function() {
        return this._current ? this._current.sess.curMembers() : this._ownSet;
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.isConsistent = function() {
        return (!this._droppedInconsistentSession &&
                (!this._previous || this._previous.sess.isConsistent()) &&
                (!this._current || this._current.sess.isConsistent()));
    };

    HybridSession.prototype._proposeGreetInit = function(include, exclude) {
        _assert(!this._ownProposalHash);
        _assert(!include.intersect(this._taskLeave).size);
        _assert(!include.intersect(this._taskExclude).size);

        if (!this._serverOrder.isSynced()) {
            throw new Error("proposal not appropriate now: need to wait for someone to include you");
        }

        var curMembers = this.curMembers();
        _assert(!include.intersect(curMembers).size);
        _assert(!exclude.subtract(curMembers).size && !exclude.has(this._owner));
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

        var parents = this._current ? this._current.sess.transcript().max() : ImmutableSet.EMPTY;
        var greetState = this._current ? this._current.greetState : null;
        var pubtxt = this._greeter.encode(greetState, curMembers, newMembers,
            GreetingMetadata.create(prevPf, prevCh, this._owner, parents));
        var pHash = utils.sha256(pubtxt);

        var p = this._setOwnProposal(prevPf, pHash);
        logger.info("proposed new greeting pHash:" + btoa(pHash) +
            ": +{" + include.toArray() + "} -{" + exclude.toArray() +
            "} from parents {" + parents.toArray().map(btoa) + "}");
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
        var ch = this._channel;
        var p = async.newPromiseAndWriters();
        var p1 = Promise.resolve(ch);

        // By protocol, leave users in taskLeave before trying to re-include them
        _assert(!include.intersect(this._taskExclude).size);
        var toLeave = include.intersect(this._taskLeave);
        if (toLeave.size) {
            p1 = p1.then(ch.execute.bind(ch, { leave: toLeave }));
        }

        // By protocol, enter users before trying to include them
        if (include.size) {
            p1 = p1.then(ch.execute.bind(ch, { enter: include }));
        }

        p1 = p1.then(this._proposeGreetInit.bind(this, include, exclude));

        // TODO(xl): [D] this could be resolved more intelligently, e.g. with PromisingSet
        this._events.subscribe(SNMembers).untilTrue(function(evt) {
            if (evt.include.equals(include) && evt.exclude.equals(exclude)) {
                p.resolve(self);
                return true;
            }
        });

        p1.catch(p.reject);
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
        var ch = this._channel;
        var p = async.newPromiseAndWriters();
        var p1 = Promise.resolve(ch);
        var cancels = [];

        if (!this._channel.curMembers()) {
            p1 = p1.then(ch.execute.bind(ch, { enter: true }));
        }

        p1 = p1.then(function() {
            if (self._channel.curMembers().size > 1) {
                // if other people already in, then wait for someone to invite us

                var estimateGKATicks = function(numberOfNewMembers) {
                    var broadcastLatency = self._flowctl.getBroadcastLatency();
                    // TODO(xl): this should be an API on Greeting
                    var extraRounds = 2;
                    var cpuTimeCost = 1000;
                    return (extraRounds + numberOfNewMembers) * (broadcastLatency + cpuTimeCost);
                };

                // fail after a while, if no-one tries to include us
                var maxAcceptableTime = estimateGKATicks(ch.curMembers().size);
                var monitor = new async.Monitor(self._timer,
                    [maxAcceptableTime], p.reject.bind(p.reject, self));
                cancels.push(monitor.stop.bind(monitor));

                // during this time, if we get auto-kicked e.g. by (rule EAL),
                // then we should auto-reenter after a timeout
                cancels.push(ch.onRecv(function(recv_in) {
                    if (recv_in.leave !== true) {
                        return;
                    }
                    var maxAcceptableTime = estimateGKATicks(recv_in.members.size);
                    monitor.reset([REENTER_GRACE_RATIO * (
                        maxAcceptableTime + self._flowctl.getBroadcastLatency())]);
                    var randomFactor = Math.random() * 0.25 + 0.5;
                    var retryTime = Math.floor(randomFactor * maxAcceptableTime);
                    logger.info("kicked from channel whilst trying to join a session; " +
                        "will retry after " + retryTime + " ticks: " + self.toString());
                    cancels.push(self._timer.after(retryTime, function() {
                        // it's hard to integrate Promised-based code with "cancels", so
                        // instead have "if" guards here to avoid doing redundant stuff
                        // in case "p.promise" settles in the meantime.
                        if (monitor.state() === "STOPPED") {
                            return;
                        }
                        return ch.execute({ enter: true }).then(function(_) {
                            if (monitor.state() === "STOPPED") {
                                return;
                            }
                            var maxAcceptableTime = estimateGKATicks(ch.curMembers().size);
                            monitor.reset([maxAcceptableTime]);
                        });
                        // if we fail to reenter, then monitor will fire p.reject later
                        // so we don't need to explicitly catch it here
                    }));
                }));
            } else {
                // no session membership change expected, just finish this operation.
                _assert(self._serverOrder.isSynced());
                p.resolve(self);
            }
        });

        cancels.push(self._events.subscribe(SNMembers).untilTrue(function(evt) {
            if (evt.remain.equals(self._ownSet) && evt.include.size) {
                p.resolve(self);
                return true;
            }
        }));

        p1.catch(p.reject);
        var cleanup = function(r) {
            async.combinedCancel(cancels)();
            return async.exitFinally(r);
        };
        return p.promise.then(cleanup, cleanup);
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
            return this._maybeLeaveChannel();
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
        var sess = this._current.sess;
        sess.sendObject(new Consistency(true));
        sess.fin();
        // try to reach consistency, then leave the channel
        sess.onFin(function(mId) {
            if (self._current && sess === self._current.sess && self._channel.curMembers()) {
                self._maybeLeaveChannel();
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
        if ("content" in action) {
            return this._current ? this._current.sess.sendData(action.content) : false;
        } else {
            return this.execute(action) !== null;
        }
    };

    /**
     * @inheritDoc
     */
    HybridSession.prototype.execute = function(action) {
        action = session.checkSessionAction(action);

        if ("content" in action) {
            throw new Error("not implemented");

        } else if ("include" in action || "exclude" in action) {
            var curMembers = this.curMembers();
            var diff = curMembers.diff(curMembers.patch([action.include, action.exclude]));
            var include = diff[0], exclude = diff[1];
            if (exclude.has(this._owner)) {
                throw new Error("cannot exclude yourself");
            } else if (!include.size && !exclude.size) {
                return Promise.resolve(this);
            }
            return this._runOwnOperation(new OwnOp("m", include, exclude),
                this._changeMembership.bind(this, include, exclude));

        } else if ("join" in action && !this._current) {
            return this._runOwnOperation(new OwnOp("j"), this._includeSelf.bind(this));

        } else if ("part" in action && this._current) {
            return this._runOwnOperation(new OwnOp("p"), this._excludeSelf.bind(this));

        } else {
            return Promise.resolve(this);
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

    /**
     * @method
     * @inheritDoc
     */
    HybridSession.prototype.onEvent = function(evtcls, prefix, useCapture) {
        return this._events.subscribe(evtcls, prefix, useCapture);
    };

    ns.HybridSession = HybridSession;

    return ns;
});
