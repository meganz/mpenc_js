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
    "mpenc/liveness",
    "mpenc/message",
    "mpenc/transcript",
    "mpenc/impl/liveness",
    "mpenc/impl/transcript",
    "mpenc/helper/assert",
    "mpenc/helper/struct",
    "mpenc/helper/async",
    "mpenc/helper/utils",
    "megalogger"
], function(session, liveness, message, transcript, livenessImpl, transcriptImpl,
    assert, struct, async, utils, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/impl/session
     * @description
     * Session related operations
     */
    var ns = {};

    var logger = MegaLogger.getLogger("session");
    var _assert = assert.assert;

    // import events
    var MsgAccepted   = transcript.MsgAccepted;
    var NotAccepted   = liveness.NotAccepted;
    var MsgFullyAcked = transcript.MsgFullyAcked;
    var NotFullyAcked = liveness.NotFullyAcked;
    var SNStateChange = session.SNStateChange;
    var SessionState = session.SessionState;

    // import components
    var Session = session.Session;
    var Flow = liveness.Flow;
    var BaseTranscript = transcriptImpl.BaseTranscript;
    var DefaultConsistencyMonitor = livenessImpl.DefaultConsistencyMonitor;

    // import message-types
    var Message = message.Message;
    var Payload = message.Payload;
    var ExplicitAck = message.ExplicitAck;
    var Consistency = message.Consistency;

    // import utils
    var Observable = async.Observable;
    var Subscribe = async.Subscribe;
    var EventContext = async.EventContext;
    var ImmutableSet = struct.ImmutableSet;
    var TrialTimeoutTarget = struct.TrialTimeoutTarget;
    var TrialBuffer = struct.TrialBuffer;
    var StateMachine = utils.StateMachine;


    var SessionContext = struct.createTupleClass("owner", "keepfresh", "timer", "flowctl", "codec", "mk_msglog");

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
        this._roTranscript = Object.create(this._transcript, { add: {} });

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
        return struct.SET_DIFF_EMPTY;
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
        return this._roTranscript;
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
        return stat.some(function(v) { return !!v; });
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
        _assert(author !== this.owner(), 'received non-duplicate message from owner');

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
            mId + ' : ' + error);
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

        var fullAcked = this._transcript.add(msg);
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
            // TODO(xl): this is hard to get right; see python for ideas
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
    return ns;
});
