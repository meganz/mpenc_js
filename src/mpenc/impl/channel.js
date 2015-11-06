/*
 * Created: 2 June 2015 Michael J.L. Holmwood <mh@mega.co.nz>
 *
 * (c) 2014-2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/channel",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "mpenc/helper/assert",
    "es6-collections",
    "jodid25519",
    "megalogger"
], function(
    channel,
    async, struct, utils, assert, es6_shim, jodid25519, MegaLogger
) {
    "use strict";

    /**
     *
     * @exports mpenc/impl/channel
     * @private
     * @description
     * <p>Implementation of the ServerOrder class from mpenc_py.</p>
     */
    var ns = {};

    var Observable = async.Observable;
    var PromisingSet = async.PromisingSet;
    var ImmutableSet = struct.ImmutableSet;
    var _assert = assert.assert;

    var logger = MegaLogger.getLogger('channel', undefined, 'mpenc');


    /**
     * A stub implementation of {@link module:mpenc/channel.GroupChannel} that
     * delegates to an even lower layer. ("You can solve any problem by
     * introducing an extra level of indirection...")
     *
     * It keeps track of some state and fills in some higher-level behaviours
     * in terms of lower-level behaviours, which it leaves unspecified. This
     * helps to reduces the amount of code that implementors must write. For
     * example, `execute` and `curMembers` are already implemented.
     *
     * Please read the documentation for `GroupChannel` before proceeding, and
     * especially the definitions of {@link module:mpenc/channel~ChannelNotice}
     * and {@link module:mpenc/channel~ChannelAction}.
     *
     * There are a few ways to build a full `GroupChannel` out of this class;
     * see the examples below. Broadly speaking, one must:
     *
     * - translate incoming received packets into `ChannelNotice` events, then
     *   pass these into `recv`.
     * - translate `ChannelAction` requests into outgoing packets, either in
     *   `onSend` or in `send`, then arrange for these packets to be sent.
     *
     * and then that should form a full implementation.
     *
     * @example
     *
     * // Receive has one main pattern:
     *
     * var groupChannel = new BaseGroupChannel();
     * var myReceiveListener = function(incomingStanza) {
     *   var channelNotices = ?translateFromXmpp(incomingStanza);
     *   channelNotices.forEach(function(evt, i, arr) {
     *     var status = groupChannel.recv(evt);
     *     assert(status);
     *   });
     * };
     * ?myXmppClientLibrary.?addReceiveListener(myReceiveListener);
     * // when we want to stop receiving
     * ?myXmppClientLibrary.?removeReceiveListener(myReceiveListener);
     *
     * // Sending has two main patterns:
     *
     * // (a) delegating to a lower layer
     *
     * var groupChannel = new BaseGroupChannel();
     * var cancelSending = groupChannel.onSend(function(channelAction) {
     *   var stanzasToSend = ?translateToXmpp(channelAction);
     *   var statuses = stanzasToSend.map(function(req, i, arr) {
     *     var didntFailImmediately = ?myXmppClientLibrary.?sendXmppStanza(req);
     *     // if this might fail later, this should still be true here
     *     return didntFailImmediately;
     *   });
     *   return statuses.every(Boolean);
     * });
     * // when we want to ignore further send requests
     * cancelSending();
     *
     * // (b) inheriting and overriding
     *
     * var MyXmppGroupChannel = function() {
     *   BaseGroupChannel.call(this);
     * };
     * MyXmppGroupChannel.prototype = Object.create(BaseGroupChannel.prototype);
     * MyXmppGroupChannel.prototype.send = function(channelAction) {
     *   // similar to what was passed into onSend() above
     * };
     * MyXmppGroupChannel.prototype.onSend = function() {
     *   throw new Error("unneeded and unused after overriding send()");
     * };
     * // but you'd need to make up your own method to "ignore" send requests
     * var groupChannel = new MyXmppGroupChannel();
     *
     * @class
     * @implements module:mpenc/channel.GroupChannel
     * @implements module:mpenc/helper/utils.SendingReceiver
     * @memberOf module:mpenc/impl/channel
     */
    var BaseGroupChannel = function() {
        this._members = null;
        this._send = new Observable();
        this._recv = new Observable();
        this._onEnter = null;
        this._onLeave = null;
        this.packetsReceived = 0;
    };

    // SendingReceiver

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.recv = function(recv_in) {
        if ("pubtxt" in recv_in) {
            _assert(this._members.value().has(recv_in.sender),
                "BaseGroupChannel received a packet from a sender not in the channel; " +
                "either your usage of it is buggy or the transport is messing with you");
            this.packetsReceived++;
        } else {
            recv_in = channel.checkChannelControl(recv_in);
            var enter = recv_in.enter;
            var leave = recv_in.leave;
            if (enter === true) {
                this._members = new PromisingSet(recv_in.members);
                if (this._onEnter) {
                    this._onEnter.resolve(this);
                    this._onEnter = null;
                }
            } else if (leave === true) {
                this._members = null;
                if (this._onLeave) {
                    this._onLeave.resolve(this);
                    this._onLeave = null;
                }
            } else {
                this._members.patch([enter, leave]);
            }
        }
        this._recv.publish(recv_in);
        return true;
    };

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.onSend = function(sub) {
        return this._send.subscribe(sub);
    };

    // GroupChannel

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.onRecv = function(sub) {
        return this._recv.subscribe(sub);
    };

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.send = function(send_out) {
        return this._send.publish(send_out).some(Boolean);
    };

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.execute = function(send_out) {
        if ("pubtxt" in send_out) {
            throw new Error("not implemented");
        } else {
            if (!this.send(send_out)) {
                return null;
            }
            send_out = channel.checkChannelControl(send_out);
            var enter = send_out.enter;
            var leave = send_out.leave;
            if (enter === true) {
                if (this._members) { // already in channel
                    return Promise.resolve(this);
                }
                if (!this._onEnter) {
                    this._onEnter = async.newPromiseAndWriters();
                }
                return this._onEnter.promise;
            } else if (leave === true) {
                if (!this._members) { // already out of channel
                    return Promise.resolve(this);
                }
                if (!this._onLeave) {
                    this._onLeave = async.newPromiseAndWriters();
                }
                return this._onLeave.promise;
            } else {
                if (!this._members) {
                    return null;
                }
                var to_enter = enter.subtract(this._members.value());
                var to_leave = leave.intersect(this._members.value());
                if (!to_enter.size && !to_leave.size) {
                    return Promise.resolve(this);
                }
                var self = this;
                return this._members.awaitDiff([to_enter, to_leave])
                    .then(function() { return self; });
            }
        }
    };

    /**
     * @inheritDoc
     */
    BaseGroupChannel.prototype.curMembers = function() {
        return this._members ? this._members.value() : null;
    };

    ns.BaseGroupChannel = BaseGroupChannel;


    /**
     * Total order on membership operations using a server to break ties.
     *
     * See "Appendix 5: Hybrid Order" in [msg-notes] for more details.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/channel
     */
    var ServerOrder = function() {
        this.clear();
    };

    /**
     * Clear the state. Call this if you have left the channel.
     */
    ServerOrder.prototype.clear = function() {
        this.seenPrevPf = new Set();

        this.packetId = null;
        this.chainHash = null;
        this.chainUnacked = null;

        this.opInitial = null;
        this.opMetadata = null;
        this.opMetadataAuthenticated = null;
        this.opFinal = null;
    };

    /**
     * @returns {string} Chain hash at the last accepted packet.
     * @throws If not yet synced.
     */
    ServerOrder.prototype.prevCh = function() {
        return this.chainHash[this.chainHash.length - 1];
    };

    /**
     * @returns {string} Packet id of the latest completed operation.
     * @throws If not yet synced.
     */
    ServerOrder.prototype.prevPf = function() {
        return this.opFinal[this.opFinal.length - 1];
    };

    ServerOrder.prototype.prevPi = function() {
        return this.opInitial[this.opInitial.length - 1];
    };

    /**
     * @returns {boolean} Whether we have synced with the existing server order.
     */
    ServerOrder.prototype.isSynced = function() {
        return this.seenPrevPf === null;
    };

    /**
     * @returns {boolean} Whether there is an ongoing operation.
     * @throws If not yet synced.
     */
    ServerOrder.prototype.hasOngoingOp = function() {
        return this.opInitial.length > this.opFinal.length;
    };

    /**
     * @param prevCh {string} Chain hash at the previous packet.
     * @param pId {string} Packet id of this packet.
     * @param [ptype] {string} Optional "packet type".
     * @returns {string} Chain hash at this packet.
     */
    ServerOrder.prototype.makeChainHash = function(prevCh, pId, ptype) {
        return utils.sha256(prevCh + pId + ptype);
    };

    /**
     * Calculate the packet-id of a packet received from the server.
     *
     * @param packet {string} Unauthenticated data received from the transport.
     * @param sender {string} Unauthenticated sender of the message.
     * @param channelMembers {module:mpenc/helper/struct.ImmutableSet}
     *      Unauthenticated membership of the group transport channel at the
     *      time that the message was received, i.e. everyone that is expected
     *      to have received this message.
     * @returns {string} packet id.
     */
    ServerOrder.prototype.makePacketId = function(packet, sender, channelMembers) {
        // Calculate the "packet-id" of a packet received from the server. The
        // reasoning behind this definition is given in msg-notes, appendix 5
        // "Hybrid ordering".
        _assert(typeof sender === "string");
        _assert(channelMembers instanceof ImmutableSet);
        _assert(channelMembers.has(sender));
        var otherRecipients = channelMembers.subtract(new ImmutableSet([sender]));
        return utils.sha256(sender + "\n" + otherRecipients.toArray().join("\n") + "\n\n" + packet);
    };

    ServerOrder.prototype._shouldSyncWith = function(pI, prevPf, forUs) {
        // [rule EIO] whether we can accept this as the first packet for our chain
        if (!forUs) {
            logger.info("ignored " + btoa(pI) + " because it's not for us");
            return false;
        } else if (this.seenPrevPf.has(prevPf)) {
            logger.info("ignored " + btoa(pI) + " because it refers to a pF " +
                btoa(prevPf) + " for which we think an earlier pI was already accepted");
            return false;
        } else {
            return true;
        }
    };

    ServerOrder.prototype._shouldAcceptInitial = function(pId, prevPf) {
        if (this.opInitial.indexOf(pId) !== -1) {
            logger.info("rejected duplicate packet: " + btoa(pId));
            return false;
        } else if (this.hasOngoingOp()) {
            logger.info("rejected pI " + btoa(pId) + " due to pending operation " +
                        btoa(this.prevPi()));
            return false;
        } else if (this.opFinal && prevPf !== this.prevPf()) {
            logger.info("rejected pI " + btoa(pId) + " because it refers to a pF which is not the " +
                        "last accepted one " + btoa(prevPf));
            return false;
        } else {
            return true;
        }
    };

    ServerOrder.prototype._shouldAcceptFinal = function(pId, prevPi) {
        if (this.opFinal.indexOf(pId) !== -1) {
            logger.info("rejected duplicate packet: " + btoa(pId));
            return false;
        } else if (!this.hasOngoingOp()) {
            logger.info("rejected pF " + btoa(pId) + " due to completed operation " +
                        btoa(this.prevPf()));
            return false;
        } else if (prevPi !== this.prevPi()) {
            logger.info("rejected pF " + btoa(pId) + " because it refers to a pI which is not the " +
                        "last accepted one " + btoa(prevPi));
            return false;
        } else {
            return true;
        }
    };

    /**
     * Sync by generating new random values.
     */
    ServerOrder.prototype.syncNew = function() {
        var pId = jodid25519.eddsa.generateKeySeed();
        return this.syncWithPrev(pId, this.makeChainHash("", pId, "\xFF"));
    };

    /**
     * Sync opportunistically with someone else's claimed previous values.
     *
     * @param prevPf {string} Packet id of the previous final packet, before we
     *      entered the channel.
     * @param prevCh {string} Chain hash at this final packet.
     */
    ServerOrder.prototype.syncWithPrev = function(prevPf, prevCh) {
        this.seenPrevPf = null;
        this.packetId = [prevPf];
        this.chainHash = [prevCh];
        this.chainUnacked = [ImmutableSet.EMPTY];
        this.opInitial = [0];
        this.opMetadata = [null];
        this.opMetadataAuthenticated = [true];
        this.opFinal = [prevPf];
        logger.info("synced serverOrder prev_pF as: " + btoa(prevPf));
    };

    ServerOrder.prototype._acceptInitial = function(pId, metadata) {
        this.opInitial.push(pId);
        this.opMetadata.push(metadata);
        this.opMetadataAuthenticated.push(false);
    };

    ServerOrder.prototype._acceptFinal = function(pId) {
        this.opFinal.push(pId);
    };

    ServerOrder.prototype._updateServerOrder = function(pId, ptype, expectToAck) {
        // update our tracking of packet ids and chain hashes, and set
        // expectations that we'll verify the consistent of them with others
        this.packetId.push(pId);
        this.chainHash.push(this.makeChainHash(this.prevCh(), pId, ptype));
        this.chainUnacked.push(ImmutableSet.from(expectToAck));
        _assert(this.packetId.length === this.chainHash.length);
    };

    /**
     * Note that we have verified the GreetingMetadata of an operation to be
     * authenticated against its claimed sender.
     */
    ServerOrder.prototype.setMetadataAuthenticated = function(prevPf) {
        var i = this.opFinal.indexOf(prevPf);
        this.opMetadataAuthenticated[i + 1] = true;
    };

    /**
     * Try to accept or reject an initial or final packet.
     *
     * @param owner {string} Owner of the local process
     * @param op {module:mpenc/greet/greeter.GreetingSummary} Operation summary
     * @param recipients {module:mpenc/helper/struct.ImmutableSet}
     *      Members (user ids) in the channel when the packet was received;
     *      includes the owner.
     * @param postAcceptInitial {function} 2-arg function called when an initial
     *      packet is accepted, taking (pI, prev_pF) packet-ids.
     * @param postAcceptFinal {function} 2-arg function called when a final
     *      packet is accepted, taking (pF, prev_pI) packet-ids.
     * @returns {boolean} Whether the packet was accepted or rejected.
     */
    ServerOrder.prototype.tryOpPacket = function(
            owner, op, recipients, postAcceptInitial, postAcceptFinal) {
        var pId = op.pId;
        var prevPf = op.isInitial() ? op.metadata.prevPf : null;
        var prevPi = op.prevPi;
        var accepted = false;
        _assert(op.isInitial() || op.isFinal());

        if (op.members.subtract(recipients).size) {
            _assert(op.isInitial());
            // [rule XP]
            logger.info("rejected " + btoa(pId) + " because it was not echoed to some members");
            return false;
        }

        if (!this.isSynced()) {
            if (op.isInitial()) {
                if (this._shouldSyncWith(pId, prevPf, op.members.has(owner))) {
                    // [rule EII] accept this opportunistically
                    this.syncWithPrev(prevPf, op.metadata.prevCh);
                } else {
                    // [rule EIO] populate the blacklist
                    this.seenPrevPf.add(prevPf);
                    return false;
                }
            } else {
                return false;
            }
        }

        if (op.isInitial()) {
            if (!this._shouldAcceptInitial(pId, prevPf)) {
                return false;
            }
            logger.info("accepted pI " + btoa(pId));
            this._acceptInitial(pId, op.metadata);
            postAcceptInitial(pId, prevPf);
            accepted = true;
        }

        if (op.isFinal()) {
            if (!this._shouldAcceptFinal(pId, prevPi)) {
                return false;
            }
            logger.info("accepted pF " + btoa(pId));
            this._acceptFinal(pId);
            postAcceptFinal(pId, prevPi);
            accepted = true;
        }

        _assert(this.hasOngoingOp() === (op.prevPi === null));
        this._updateServerOrder(pId, op.packetType(), op.members);
        return accepted;
    };

    ServerOrder.prototype.acceptLeavePacket = function(leavers, channelMembers, sessionMembers) {
        _assert(this.hasOngoingOp());
        // fake packet-id as defined by msg-notes, appendix 5
        var pId = this.makePacketId(
            "\xffleave " + this.prevPi() + "\n" + leavers.toArray(),
            "__server__", channelMembers.union(new ImmutableSet(["__server__"])));
        logger.info("accepted pF " + btoa(pId) + ", a pseudo-packet for members leaving: " + leavers.toArray());
        this._acceptFinal(pId);
        this._updateServerOrder(pId, "\xffleave", sessionMembers.subtract(leavers));
    };

    ns.ServerOrder = ServerOrder;


    return ns;
});
