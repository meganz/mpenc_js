/*
 * Created: 16 Feb 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Wellsford, New Zealand
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
    "mpenc/helper/assert",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "mpenc/codec",
    "asmcrypto",
    "jodid25519",
    "megalogger",
], function(assert, struct, utils, codec, asmCrypto, jodid25519, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/message
     * @description
     * Message interfaces.
     */
    var ns = {};

    var _assert = assert.assert;
    var _T = codec.TLV_TYPE;

    var logger = MegaLogger.getLogger('message', undefined, 'mpenc');

    var ImmutableSet = struct.ImmutableSet;

    /**
     * A Message object, sent by a user.
     *
     * @interface
     * @memberOf module:mpenc/message
     */
    var Message = function(mId, author, parents, recipients, body) {
        if (!(this instanceof Message)) { return new Message(mId, author, parents, recipients, body); }

        if (mId === null || mId === undefined) {
            throw new Error("invalid empty mId");
        }
        if (author === null || author === undefined) {
            throw new Error("invalid empty uId");
        }
        if (parents === null || parents === undefined) {
            throw new Error("invalid empty parents");
        }
        if (recipients === null || recipients === undefined) {
            throw new Error("invalid empty recipients");
        }

        parents = new ImmutableSet(parents);
        if (parents.has(null) || parents.has(undefined)) {
            throw new Error("invalid parents: has empty value");
        }
        recipients = new ImmutableSet(recipients);
        if (recipients.has(null) || recipients.has(undefined)) {
            throw new Error("invalid recipients: has empty value");
        }

        this.mId = mId;
        this.author = author;
        this.parents = new ImmutableSet(parents);
        this.recipients = new ImmutableSet(recipients);
        this.body = body;
    };

    /**
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/message.Message} Message object for the id. */
    Message.prototype.members = function() {
        return this.recipients.union(new ImmutableSet([this.author]));
    };

    Object.freeze(Message.prototype);
    ns.Message = Message;

    /**
     * Message body object.
     */
    var MessageBody = function() {};

    MessageBody.prototype = Object.create(Array.prototype);

    Object.freeze(MessageBody.prototype);
    ns.MessageBody = MessageBody;

    /**
     * Message actively sent by a user, to be consumed by the application.
     *
     * @property body {string} Body of the message.
     */
    var Payload = struct.createTupleClass(MessageBody, "content");

    Payload.prototype.postInit = function() {
        if (!(typeof this.content === "string" && this.content.length)) {
            throw new Error("Payload content must be non-empty");
        }
    };

    Object.freeze(Payload.prototype);
    ns.Payload = Payload;

    /**
     * Explicit ack of the message parents.
     *
     * All messages implicitly ack their ancestors, but sometimes we must do an
     * explicit ack when no other message was (or is planned to be) sent.
     *
     * Explicit acks themselves need not be automatically acked, nor do they need
     * to have ack-monitors set on them. As a caveat, ack-monitors of other types
     * of messages should also handle (e.g. resend) explicit acks that were sent
     * directly before it - since there is no other ack-monitor to handle these.
     *
     * @property manual {boolean} Whether this was sent with conscious user oversight.
     */
    var ExplicitAck = struct.createTupleClass(MessageBody, "manual");

    ExplicitAck.prototype.postInit = function() {
        if (this.manual !== (!!this.manual)) {
            throw new Error("ExplicitAck manual must be boolean");
        }
    };

    Object.freeze(ExplicitAck.prototype);
    ns.ExplicitAck = ExplicitAck;

    var HeartBeat = {}; // TODO(xl): TBA

    /**
     * Request immediate acks from others so that consistency can be reached.
     * This is useful e.g. when changing the membership of the channel, and you
     * want to check consistency of the history with the previous membership.
     *
     * @property close {boolean} If true, this is a commitment that the author
     *      will send no more Payload messages to the session, and that they
     *      will ignore the content of later messages by others, except to
     *      treat it as an ack of this message. After this is fully-acked,
     *      other members should formally exclude the author from the session,
     *      e.g. by running a greeting protocol.
     */
    var Consistency = struct.createTupleClass(MessageBody, "close");

    Consistency.isFin = function(obj) {
        return (obj instanceof Consistency) && obj.close;
    };

    Consistency.prototype.postInit = function() {
        if (this.close !== (!!this.close)) {
            throw new Error("Consistency close must be boolean");
        }
    };

    Object.freeze(Consistency.prototype);
    ns.Consistency = Consistency;


    var MESSAGE_BODY_TYPES = [
        Payload,            // 0x00
        ExplicitAck,        // 0x01
        HeartBeat,          // 0x02
        Consistency,        // 0x03
    ];

    /**
     * Object for converting MessageBody to/from string representation.
     */
    var DefaultMessageCodec = {
        // TODO(xl): maybe move this as static methods of MessageBody
        // and/or use TLV-based encoding to be consistent

        encode: function(body) {
            if (!(body instanceof MessageBody)) {
                throw new Error("tried to encode non-MessageBody: " + body);
            }
            var type = String.fromCharCode(MESSAGE_BODY_TYPES.indexOf(body.constructor));
            _assert(type.length === 1);
            return type + JSON.stringify(body.slice());
        },

        decode: function(data) {
            var type = data[0], body = JSON.parse(data.substring(1));
            var cls = MESSAGE_BODY_TYPES[type.charCodeAt(0)];
            if (!(body instanceof Array)) {
                throw new Error("bad decode: not an Array: " + body);
            }
            return new (Function.prototype.bind.apply(cls, [undefined].concat(body)))();
        },

    };
    ns.DefaultMessageCodec = DefaultMessageCodec;

    return ns;
});
