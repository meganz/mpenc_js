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
    "mpenc/channel",
    "mpenc/impl/channel",
    "mpenc/message",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "mpenc/helper/assert",
    "es6-collections",
    "megalogger"
], function(
    channel, channelImpl, message,
    async, struct, utils, assert, es6_shim, MegaLogger
) {
    "use strict";

    /**
     *
     * @exports mpenc/impl/dummy
     * @private
     * @description
     * <p>Dummy implementations of various interfaces for testing.</p>
     */
    var ns = {};

    var ImmutableSet = struct.ImmutableSet;
    var BaseGroupChannel = channelImpl.BaseGroupChannel;
    var DecryptVerifyError = message.DecryptVerifyError;

    var _assert = assert.assert;

    var logger = MegaLogger.getLogger('dummy', undefined, 'mpenc');


    /**
     * Dummy {@link module:mpenc/message.MessageSecurity} used for testing.
     *
     * The <code>greetState</code> parameter is assumed to contain a <code>
     * sessionId</code> field which is a string.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/dummy
     */
    var DummyMessageSecurity = function(greetState) {
        var sId = greetState.sessionId;
        var stub = function() {};
        return {
            authEncrypt: function(ts, message) {
                var pubtxt = JSON.stringify({
                    sId: btoa(sId),
                    author: message.author,
                    parents: message.parents.toArray().map(btoa),
                    readers: message.readers.toArray(),
                    sectxt: btoa(message.body)
                });
                return {
                    pubtxt: pubtxt,
                    secrets: {
                        commit: stub,
                        destroy: stub,
                        mId: btoa(utils.sha256(pubtxt)),
                    },
                };
            },
            decryptVerify: function(ts, pubtxt, sender) {
                if (pubtxt.charAt(0) !== "{") {
                    throw new DecryptVerifyError("PacketRejected");
                }
                var body = JSON.parse(pubtxt);
                if (atob(body.sId) !== sId) {
                    throw new DecryptVerifyError("PacketRejected: not our expected sId " + btoa(sId) + "; actual " + body.sId);
                }
                body.parents = body.parents.map(atob);
                body.body = atob(body.sectxt);
                return {
                    message: body,
                    secrets: {
                        commit: stub,
                        destroy: stub,
                        mId: btoa(utils.sha256(pubtxt)),
                    },
                };
            },
        };
    };

    ns.DummyMessageSecurity = DummyMessageSecurity;


    /**
     * Dummy flow control object used for testing.
     *
     * (FlowControl is not yet defined in the JS library; it will be ported
     * soon from the python.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/dummy
     */
    var DummyFlowControl = function() {
        return {
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
    };

    ns.DummyFlowControl = DummyFlowControl;


    /**
     * A dummy implementation of an MUC server, with one single group channel.
     *
     * @class
     * @private
     * @memberOf module:mpenc/impl/dummy
     */
    var DummyGroupServer = function() {
        this._channels = new Map();
        this._queues = new Map();
        this._incoming = [];
        // current members; takes into account all packets placed on users'
        // recv-queues but not the server incoming queue
        this._members = ImmutableSet.EMPTY;
    };

    /**
     * Receive and process a packet that was previously sent to us. This puts
     * relevant ChannelNotice objects (if any) onto relevant users' recv-queues.
     *
     * @param [index] {number} The index in the incoming-queue of the packet to
     *      process. By default this is 0, but one can change this to simulate
     *      different senders being slower than others at reaching the server.
     *      The order of packets from *one* sender should still be the same.
     * @throws If you try to call this with an index, for which another packet
     *      with the same sender occurs at a lower index.
     */
    DummyGroupServer.prototype.recv = function(index) {
        index = index || 0;
        if (!this._incoming.length) {
            throw new Error("recv queue is empty");
        }

        var sender = this._incoming[index].sender;
        for (var i = 0; i < index; i++) {
            if (this._incoming[i].sender === sender) {
                // we're not modelling a malicious server here, disallow this for now
                throw new Error("not supposed to deliver *one sender's* packets out-of-order");
            }
        }

        var incoming = this._incoming.splice(index, 1)[0];
        _assert(incoming.sender === sender);
        var recv_in = incoming.action;
        var self = this;

        if (!this._members.has(sender) && (recv_in.leave !== undefined || recv_in.enter !== true)) {
            // not in channel, commands have no effect except enter: true
            logger.info("sender already left the channel, ignoring packet: " + recv_in);
            return true;
        }

        // process a message

        if ("pubtxt" in recv_in) {
            if (recv_in.recipients.subtract(this._members).size) {
                var left = recv_in.recipients.subtract(this._members);
                var remain = recv_in.recipients.intersect(this._members);
                var others = this._members.subtract(remain);
                logger.info("some members already left: " + left.toArray() +
                    "; sent to remaining: [" + remain.toArray() +
                    "]; and also: [" + others.toArray() + "]");
            }
            this._members.forEach(function(id) {
                self._queues.get(id).push({ pubtxt: recv_in.pubtxt, sender: sender });
            });
            return true;
        }

        // process a membership change

        recv_in = channel.checkChannelControl(recv_in);

        var enter = recv_in.enter;
        var leave = recv_in.leave;
        // log ignored stuff
        var to_enter = ImmutableSet.from((enter === true) ? [sender] : enter);
        var to_leave = ImmutableSet.from((leave === true) ? [sender] : leave);
        var done_enter = to_enter.intersect(this._members);
        var done_leave = to_leave.subtract(this._members);
        if (done_enter.size) {
            logger.info("tried to add some members but they already entered: " + done_enter.toArray());
            to_enter = to_enter.subtract(this._members);
        }
        if (done_leave.size) {
            logger.info("tried to remove some members but they already left: " + done_leave.toArray());
            to_leave = to_leave.intersect(this._members);
        }
        if (!to_enter.size && !to_leave.size) {
            return true;
        }
        var old_members = this._members;
        var to_remain = this._members.subtract(to_leave);
        this._members = to_remain.union(to_enter);

        to_remain.forEach(function(id) {
            self._queues.get(id).push({ enter: to_enter, leave: to_leave });
        });
        to_enter.forEach(function(id) {
            self.getChannel(id); // make sure new members have a queue
            self._queues.get(id).push({ enter: true, members: self._members });
        });
        to_leave.forEach(function(id) {
            self._queues.get(id).push({ leave: true, members: old_members });
        });

        return true;
    };

    /**
     * Process all packets in the incoming queue in the original order.
     *
     * @return {number} Number of receives executed.
     */
    DummyGroupServer.prototype.recvAll = function() {
        var count = 0;
        while (this._incoming.length) {
            this.recv();
            count++;
        }
        return count;
    };

    /**
     * For a given recipient, deliver the next packet in their recv-queue.
     *
     * @param [id] {string} Recipient to deliver to. By default, the sender
     *      selected by <code>selectNextSendTarget</code>.
     */
    DummyGroupServer.prototype.send = function(id) {
        id = id || this.selectNextSendTarget();
        if (!this._channels.has(id)) {
            throw new Error("server doesn't know about id");
        }
        var recv_in = this._queues.get(id).shift();
        return this._channels.get(id).recv(recv_in);
    };

    /**
     * Deliver all packets in all users' recv-queues.
     *
     * @return {number} Number of sends executed.
     */
    DummyGroupServer.prototype.sendAll = function() {
        var count = 0;
        var id;
        while ((id = this.selectNextSendTarget()) !== null) {
            this.send(id);
            count++;
        }
        return count;
    };

    /**
     * Select the next member to deliver a packet to; i.e. the one with the
     * longest queue of undelivered packets.
     */
    DummyGroupServer.prototype.selectNextSendTarget = function() {
        var len = 0;
        var curId = null;
        this._queues.forEach(function(queue, id) {
            if (queue.length > len) {
                len = queue.length;
                curId = id;
            }
        });
        return curId;
    };

    /**
     * Keep alternately running <code>recvAll</code> and <code>sendAll</code>
     * until one of them returns zero (i.e. there was nothing to do).
     */
    DummyGroupServer.prototype.run = function() {
        while (true) {
            if (!this.recvAll()) { break; }
            if (!this.sendAll()) { break; }
        }
    };

    /**
     * Keep alternately running <code>recvAll</code> and <code>sendAll</code>
     * until one of them returns zero (i.e. there was nothing to do).
     *
     * This works asynchronously, even if things are added onto the server
     * queues via <code>Promises</code>, which in Javascript runs *after* the
     * current event tick.
     */
    DummyGroupServer.prototype.runAsync = function(graceTicks, timer) {
        graceTicks = graceTicks === undefined ? 16 : graceTicks;
        if (!this.recvAll() && !this.sendAll()) {
            // nothing was done
            if (!graceTicks) {
                logger.info("runAsync gave up after some ticks with no activity");
                return;
            }
            graceTicks--;
        } else {
            this.run();
        }
        // execute ourselves asynchronously in case e.g. a Promise resolves
        var condition = timer ? async.timeoutPromise(timer, 1) : true;
        Promise.resolve(condition)
            .then(this.runAsync.bind(this, graceTicks, timer))
            .catch(logger.warn.bind(logger));
    };

    /**
     * Get a GroupChannel object for the given user.
     *
     * @returns {module:mpenc/channel.GroupChannel}
     */
    DummyGroupServer.prototype.getChannel = function(id) {
        if (!this._channels.has(id)) {
            var self = this;
            var channel = new BaseGroupChannel();
            channel.onSend(function(send_out) {
                return self._incoming.push({ sender: id, action: send_out });
            });
            this._channels.set(id, channel);
            this._queues.set(id, []);
        }
        return this._channels.get(id);
    };

    /**
     * @returns {module:mpenc/helper/struct.ImmutableSet} Current members.
     */
    DummyGroupServer.prototype.curMembers = function() {
        return this._members;
    };

    ns.DummyGroupServer = DummyGroupServer;


    return ns;
});
