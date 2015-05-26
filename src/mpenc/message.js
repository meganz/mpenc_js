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

    var Set = struct.ImmutableSet;

    /**
     * A Message object, sent by a user.
     *
     * @interface
     * @memberOf module:mpenc/message
     */
    var Message = function(mId, author, parents, recipients, body) {
        if (!(this instanceof Message)) return new Message(mId, author, parents, recipients, body);

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

        parents = new Set(parents);
        if (parents.has(null) || parents.has(undefined)) {
            throw new Error("invalid parents: has empty value");
        }
        recipients = new Set(recipients);
        if (recipients.has(null) || recipients.has(undefined)) {
            throw new Error("invalid recipients: has empty value");
        }

        this.mId = mId;
        this.author = author;
        this.parents = new Set(parents);
        this.recipients = new Set(recipients);
        this.body = body;
    };

    /**
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/message.Message} Message object for the id. */
    Message.prototype.members = function() {
        return this.recipients.union(new Set([this.author]));
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

    Object.freeze(ExplicitAck.prototype);
    ns.ExplicitAck = ExplicitAck;

    // TODO: messaging-level metadata like ExplicitAck, HeartBeat, Consistency


    var _createMessageId = function(signature, content) {
        // ignore sidkeyHint since that's unauthenticated
        return utils.sha256(signature + content).slice(0, 20);
    };

    /**
     * Component that holds cryptographic state needed to encrypt/decrypt
     * messages that are part of a session.
     *
     * @class
     * @memberOf module:mpenc/message
     */
    var MessageSecurity = function(owner, ephemeralPrivKey, ephemeralPubKey, sessionKeyStore) {
        this.owner = owner;
        this._privKey = ephemeralPrivKey;
        this._pubKey = ephemeralPubKey;
        this._sessionKeyStore = sessionKeyStore;
    };

    /**
     * Encodes a given data message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param author {string}
     *     Author of the message.
     * @param recipients {module:mpenc/helper/struct.ImmutableSet}
     *     Recipients of the message.
     * @param parents {?module:mpenc/helper/struct.ImmutableSet}
     *     Parent message ids.
     * @param body {string}
     *     Message body as byte string.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {{ mId: string, ciphertext: string}}
     *     Message id and ciphertext.
     */
    MessageSecurity.prototype.encrypt = function(body, recipients, parents, paddingSize) {
        var privKey = this._privKey;
        var pubKey = this._pubKey;
        var sessionKeyStore = this._sessionKeyStore;
        paddingSize = paddingSize | 0;

        // We want message attributes in this order:
        // sid/key hint, message signature, protocol version, message type,
        // iv, message data
        var sessionID = sessionKeyStore.sessionIDs[0];
        var groupKey = sessionKeyStore.sessions[sessionID].groupKeys[0];
        var members = recipients.union(new Set([this.owner]));
        _assert(members.equals(new Set(sessionKeyStore.sessions[sessionID].members)));

        // Three portions: unsigned content (hint), signature, rest.
        // Compute info for the SIDKEY_HINT and signature.
        var sidkeyHash = utils.sha256(sessionID + groupKey);

        // Rest (protocol version, message type, iv, message data).
        var content = codec.ENCODED_VERSION + codec.ENCODED_TYPE_DATA;

        // Encryption payload
        var rawBody = "";
        if (parents && parents.forEach) {
            parents.forEach(function(pmId) {
                rawBody += codec.encodeTLV(codec.TLV_TYPE.MESSAGE_PARENT, pmId);
            });
        }
        // Protect multi-byte characters
        body = unescape(encodeURIComponent(body));
        rawBody += codec.encodeTLV(codec.TLV_TYPE.MESSAGE_BODY, body);

        var encrypted = ns._encryptRaw(rawBody, groupKey, paddingSize);
        content += codec.encodeTLV(codec.TLV_TYPE.MESSAGE_IV, encrypted.iv);
        content += codec.encodeTLV(codec.TLV_TYPE.MESSAGE_PAYLOAD, encrypted.data);

        // Compute the content signature.
        var signature = codec.signMessage(codec.MESSAGE_TYPE.MPENC_DATA_MESSAGE,
                                          content, privKey, pubKey, sidkeyHash);

        // Assemble everything.
        var out = codec.encodeTLV(codec.TLV_TYPE.SIDKEY_HINT, sidkeyHash[0]);
        out += codec.encodeTLV(codec.TLV_TYPE.MESSAGE_SIGNATURE, signature);
        out += content;

        return { mId: _createMessageId(signature, content), ciphertext: out };
    };

    /**
     * Encrypts a given data message.
     *
     * The data message is encrypted using AES-128-CTR, and a new random
     * IV/nonce (12 byte) is generated and returned.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {Object}
     *     An object containing the message (in `data`, binary string) and
     *     the IV used (in `iv`, binary string).
     */
    ns._encryptRaw = function(dataBytes, key, paddingSize) {
        paddingSize = paddingSize | 0;
        var keyBytes = new Uint8Array(jodid25519.utils.string2bytes(key));
        var nonceBytes = utils._newKey08(96);
        // Prepend length in bytes to message.
        _assert(dataBytes.length < 0xffff,
                'Message size too large for encryption scheme.');
        dataBytes = codec._short2bin(dataBytes.length) + dataBytes;
        if (paddingSize) {
            // Compute exponential padding size.
            var exponentialPaddingSize = paddingSize
                                       * (1 << Math.ceil(Math.log(Math.ceil((dataBytes.length) / paddingSize))
                                                         / Math.log(2))) + 1;
            var numPaddingBytes = exponentialPaddingSize - dataBytes.length;
            dataBytes += (new Array(numPaddingBytes)).join('\u0000');
        }
        var ivBytes = new Uint8Array(nonceBytes.concat(utils.arrayMaker(4, 0)));
        var cipherBytes = asmCrypto.AES_CTR.encrypt(dataBytes, keyBytes, ivBytes);
        return { data: jodid25519.utils.bytes2string(cipherBytes),
                 iv: jodid25519.utils.bytes2string(nonceBytes) };
    };

    /**
     * Decodes a given TLV encoded data message into an object.
     *
     * @param message {string}
     *     A TLV string for the message.
     * @param authorHint {string}
     *     Claimed (unverified) author for the message.
     * @returns {mpenc.message.Message}
     *     Message as JavaScript object.
     */
    MessageSecurity.prototype.decrypt = function(message, authorHint) {
        var sessionKeyStore = this._sessionKeyStore;

        var sessionID = sessionKeyStore.sessionIDs[0];
        var groupKey = sessionKeyStore.sessions[sessionID].groupKeys[0];

        if (!authorHint) {
            logger.warn('No message author for message available, '
                        + 'will not be able to decrypt: ' + message);
            return null;
        }

        var signingPubKey = sessionKeyStore.pubKeyMap[authorHint];
        var inspected = _inspect(message);
        var decoded = null;

        // Loop over (session ID, group key) combos, starting with the latest.
        outer: // Label to break out of outer loop.
        for (var sidNo in sessionKeyStore.sessionIDs) {
            var sessionID = sessionKeyStore.sessionIDs[sidNo];
            var session = sessionKeyStore.sessions[sessionID];
            for (var gkNo in session.groupKeys) {
                var groupKey = session.groupKeys[gkNo];
                var sidkeyHash = utils.sha256(sessionID + groupKey);
                if (inspected.sidkeyHint === sidkeyHash[0]) {
                    var verifySig = codec.verifyMessageSignature(codec.MESSAGE_TYPE.MPENC_DATA_MESSAGE,
                                                                 inspected.rawMessage,
                                                                 inspected.signature,
                                                                 signingPubKey,
                                                                 sidkeyHash);
                    if (verifySig === true) {
                        decoded = _decrypt(inspected,
                                           groupKey,
                                           authorHint,
                                           session.members);
                        break outer;
                    }
                    // TODO: maybe log bad signatures
                }
            }
        }

        if (!decoded) {
            return null;
        }

        logger.debug('Message from "' + authorHint + '" successfully decrypted.');
        return decoded;
    };

    var _decrypt = function(inspected, groupKey, author, members) {
        var debugOutput = [];
        var out = _decode(inspected.rawMessage);
        _assert(out.data);

        // Data message signatures were already verified through trial decryption.
        var rest = ns._decryptRaw(out.data, groupKey, out.iv);

        var encrypted = ns._encryptRaw(codec.encodeTLV(codec.TLV_TYPE.MESSAGE_BODY, rest), groupKey, 0);

        var parents = [];
        rest = codec.popTLVAll(rest, _T.MESSAGE_PARENT, function(value) {
            parents.push(value);
            debugOutput.push('parent: ' + btoa(value));
        });

        var data;
        rest = codec.popTLV(rest, _T.MESSAGE_BODY, function(value) {
            // Undo protection for multi-byte characters.
            data = decodeURIComponent(escape(value));
            debugOutput.push('body: ' + value);
        });

        logger.debug('mpENC decrypted message debug: ', debugOutput);

        var idx = members.indexOf(author);
        _assert(idx >= 0);
        var recipients = members.slice();
        recipients.splice(idx, 1);

        var mId = _createMessageId(inspected.signature, inspected.rawMessage);
        return new Message(mId, author, parents, recipients, Payload(data));
    };

    var _decode = function(rawMessage) {
        // full decode, no crypto operations
        var debugOutput = [];
        var out = {};
        var rest = rawMessage;

        rest = codec.popStandardFields(rest,
            codec.MESSAGE_TYPE.MPENC_DATA_MESSAGE, debugOutput);

        rest = codec.popTLV(rest, _T.MESSAGE_IV, function(value) {
            out.iv = value;
            debugOutput.push('messageIV: ' + btoa(value));
        });

        rest = codec.popTLV(rest, _T.MESSAGE_PAYLOAD, function(value) {
            out.data = value;
            debugOutput.push('rawDataMessage: ' + btoa(out.data));
        });

        // TODO(xl): maybe complain if too much junk afterwards
        // Debugging output.
        logger.debug('mpENC decoded message debug: ', debugOutput);
        return out;
    };

    var _inspect = function(message, debugOutput) {
        // partial decode, no crypto operations
        var debugOutput = debugOutput || [];
        var out = {};
        var rest = message;

        rest = codec.popTLV(rest, _T.SIDKEY_HINT, function(value) {
            value.length === 1 || codec.decodeError("unexpected length for SIDKEY_HINT");
            out.sidkeyHint = value;
            debugOutput.push('sidkeyHint: 0x'
                             + value.charCodeAt(0).toString(16));
        });

        rest = codec.popTLV(rest, _T.MESSAGE_SIGNATURE, function(value) {
            out.signature = value;
            debugOutput.push('messageSignature: ' + btoa(value));
        });
        out.rawMessage = rest;

        return out;
    }

    /**
     * Decrypts a given data message.
     *
     * The data message is decrypted using AES-128-CTR.
     *
     * @param data {string}
     *     Binary string data message.
     * @param key {string}
     *     Binary string representation of 128-bit encryption key.
     * @param iv {string}
     *     Binary string representation of 96-bit nonce/IV.
     * @returns {string}
     *     The clear text message as a binary string.
     */
    ns._decryptRaw = function(data, key, iv) {
        if (data === null || data === undefined) {
            return null;
        }
        var keyBytes = new Uint8Array(jodid25519.utils.string2bytes(key));
        var nonceBytes = jodid25519.utils.string2bytes(iv);
        var ivBytes = new Uint8Array(nonceBytes.concat(utils.arrayMaker(4, 0)));
        var clearBytes = asmCrypto.AES_CTR.decrypt(data, keyBytes, ivBytes);
        // Strip off message size and zero padding.
        var clearString = jodid25519.utils.bytes2string(clearBytes);
        var messageSize = codec._bin2short(clearString.slice(0, 2));
        clearString = clearString.slice(2, messageSize + 2);
        return clearString;
    };

    ns.MessageSecurity = MessageSecurity;


    return ns;
});
