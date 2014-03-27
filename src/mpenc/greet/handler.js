/**
 * @fileOverview
 * Implementation of a protocol handler with its state machine.
 */

(function() {
    "use strict";

    /**
     * @namespace
     * Implementation of a protocol handler with its state machine.
     *
     * @description
     * <p>Implementation of a protocol handler with its state machine.</p>
     *
     * <p>
     * This protocol handler manages the message flow for user authentication,
     * authenticated signature key exchange, and group key agreement.</p>
     *
     * <p>
     * This implementation is using the an authenticated signature key exchange that
     * also provides participant authentication as well as a CLIQUES-based group
     * key agreement.</p>
     */
    mpenc.handler = {};

    var _assert = mpenc.assert.assert;

    /*
     * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
     *
     * (c) 2014 by Mega Limited, Wellsford, New Zealand
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

    /**
     * Carries message content for the mpEnc protocol flow.
     *
     * @constructor
     * @param source
     *     Message originator (from).
     * @param dest
     *     Message destination (to).
     * @param agreement
     *     Type of key agreement. "initial" or "auxilliary".
     * @param flow
     *     Direction of message flow. "upflow" or "downflow".
     * @param members
     *     List (array) of all participating members.
     * @param intKeys
     *     List (array) of intermediate keys for group key agreement.
     * @param nonces
     *     Nonces of members for ASKE.
     * @param pubKeys
     *     List (array) of all participants' ephemeral public keys.
     * @param sessionSignature
     *     Signature to acknowledge the session.
     * @returns {ProtocolMessage}
     *
     * @property source
     *     Message originator (from).
     * @property dest
     *     Message destination (to).
     * @property agreement
     *     Type of key agreement. "initial" or "auxilliary".
     * @property flow
     *     Direction of message flow. "upflow" or "downflow".
     * @property members
     *     List (array) of all participating members.
     * @property intKeys
     *     List (array) of intermediate keys for group key agreement.
     * @property debugKeys
     *     List (array) of keying debugging strings.
     * @property nonces
     *     Nonces of members for ASKE.
     * @property pubKeys
     *     Ephemeral public signing key of members.
     * @property sessionSignature
     *     Session acknowledgement signature using sender's static key.
     */
    mpenc.handler.ProtocolMessage = function(source, dest, agreement, flow, members,
                                             intKeys, debugKeys, nonces, pubKeys,
                                             sessionSignature) {
        this.source = source || '';
        this.dest = dest || '';
        this.agreement = agreement || '';
        this.flow = flow || '';
        this.members = members || [];
        this.intKeys = intKeys || [];
        this.debugKeys = debugKeys || [];
        this.nonces = nonces || [];
        this.pubKeys = pubKeys || [];
        this.sessionSignature = sessionSignature || null;

        return this;
    };


    /**
     * Implementation of a protocol handler with its state machine.
     *
     * @constructor
     * @param id {string}
     *     Member's identifier string.
     * @param privKey
     *     This participant's static/long term private key.
     * @param pubKey
     *     This participant's static/long term public key.
     * @param staticPubKeyDir
     *     An object with a `get(key)` method, returning the static public key of
     *     indicated by member ID `ky`.
     * @returns {ProtocolHandler}
     *
     * @property id {string}
     *     Member's identifier string.
     * @property privKey
     *     This participant's static/long term private key.
     * @property pubKey
     *     This participant's static/long term public key.
     * @property staticPubKeyDir
     *     An object with a `get(key)` method, returning the static public key of
     *     indicated by member ID `ky`.
     * @property protocolOutQueue
     *     Queue for outgoing protocol related (non-user) messages, prioritised
     *     in processing over user messages.
     * @property messageOutQueue
     *     Queue for outgoing user content messages.
     * @property uiQueue
     *     Queue for messages to display in the UI. Contains objects with
     *     attributes `type` (can be strings 'message', 'info', 'warn' and
     *     'error') and `message`.
     * @property askeMember
     *     A {SignatureKeyExchangeMember} object with the same participant ID.
     * @property cliquesMember
     *     A {CliquesMember} object with the same participant ID.
     */
    mpenc.handler.ProtocolHandler = function(id, privKey, pubKey, staticPubKeyDir) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.protocolOutQueue = [];
        this.messageOutQueue = [];
        this.uiQueue = [];

        // Sanity check.
        _assert(this.id && this.privKey && this.pubKey && this.staticPubKeyDir,
                'Constructor call missing required parameters.');

        // Make protocol handlers for sub tasks.
        this.cliquesMember = new mpenc.cliques.CliquesMember(this.id);
        this.askeMember = new mpenc.ske.SignatureKeyExchangeMember(this.id);
        this.askeMember.staticPrivKey = privKey;
        this.askeMember.staticPubKeyDir = staticPubKeyDir;

        return this;
    };


    /**
     * Start the protocol negotiation with the group participants..
     *
     * @method
     * @param otherMembers
     *     Iterable of other members for the group (excluding self).
     * @returns
     *     Wire encoded {ProtocolMessage} content.
     */
    mpenc.handler.ProtocolHandler.prototype.start = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        return mpenc.codec.encodeMessage(this._mergeMessages(cliquesMessage, askeMessage));
    };


    /**
     * Start a new upflow for joining new members..
     *
     * @method
     * @param newMembers
     *     Iterable of new members to join the group.
     * @returns
     *     Wire encoded {ProtocolMessage} content.
     */
    mpenc.handler.ProtocolHandler.prototype.join = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        return mpenc.codec.encodeMessage(this._mergeMessages(cliquesMessage, askeMessage));
    };


    /**
     * Start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers
     *     Iterable of members to exclude from the group.
     * @returns
     *     Wire encoded {ProtocolMessage} content.
     */
    mpenc.handler.ProtocolHandler.prototype.exclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        return mpenc.codec.encodeMessage(this._mergeMessages(cliquesMessage, askeMessage));
    };


    /**
     * Refresh group key.
     *
     * @returns
     *     Wire encoded {ProtocolMessage} content.
     * @method
     */
    mpenc.handler.ProtocolHandler.prototype.refresh = function() {
        var cliquesMessage = this.cliquesMember.akaRefresh();

        return mpenc.codec.encodeMessage(this._mergeMessages(cliquesMessage, null));
    };


    /**
     * Handles mpEnc protocol message processing.
     *
     * @method
     * @param wireMessage
     *     Received message (wire encoded). See {@link ProtocolMessage}.
     */
    mpenc.handler.ProtocolHandler.prototype.processMessage = function(wireMessage) {
        // FIXME: Rework in a way to fit the Karere filter model, as e. g. in
        // https://code.developers.mega.co.nz/messenger/karere/blob/feature-karere/js/chat/capslockFilterDemo.js#L32
        // https://code.developers.mega.co.nz/messenger/karere/blob/feature-karere/js/chat/emoticonsFilter.js#L45
        // * Use message meta-data (eventData.from) to identify sender.
        // * Access content from eventData.messageHtml and/or eventData.message
        var classify = mpenc.codec.categoriseMessage(wireMessage);

        if (!classify) {
            return;
        }

        switch (classify.category) {
            case mpenc.codec.MESSAGE_CATEGORY.MPENC_ERROR:
                this.uiQueue.push({
                        type: 'error',
                        message: 'Error in mpEnc protocol: ' + classify.content
                    });
                break;
            case mpenc.codec.MESSAGE_CATEGORY.PLAIN:
                this.protocolOutQueue.push(mpenc.codec.getQueryMessage(
                    "We're not dealing with plaintext messages. Let's negotiate mpENC communication."));
                this.uiQueue.push({
                        type: 'info',
                        message: 'Received unencrypted message, requesting encryption.'
                    });
                break;
            case mpenc.codec.MESSAGE_CATEGORY.MPENC_QUERY:
                // TODO: Start process:
                // * Find sender (use eventData.from)
                // * call this.start(otherMembers);
                // * enqueue message returned from start()
                dump('*** Starting mpEnc keying with other members. ***');
                break;
            case mpenc.codec.MESSAGE_CATEGORY.MPENC_MESSAGE:
                var decodedMessage = mpenc.codec.decodeMessageContent(classify.content);
                if (decodedMessage.data !== undefined) {
                    // This is a normal communication message.
                    if (decodedMessage.signatureOk === false) {
                        // Signature failed, abort!
                        this.uiQueue.push({
                            type: 'error',
                            message: 'Signature of received message invalid.'
                        });
                    } else {
                        this.uiQueue.push({
                            type: 'message',
                            message: decodedMessage.data
                        });
                    }
                } else {
                    // This is a keying message.
                    var outMessage = this.processKeyingMessage(decodedMessage);
                    if (outMessage) {
                        this.protocolOutQueue.push(mpenc.codec.encodeMessage(outMessage));
                    }
                }
                break;
            default:
                _assert(false, 'Received unknown message category: ' + classify.category);
                break;
        }
    };


    /**
     * Handles keying protocol execution with all participants.
     *
     * @method
     * @param message
     *     Received message (decoded). See {@link ProtocolMessage}.
     * @returns {ProtocolMessage}
     *     Un-encoded message content.
     */
    mpenc.handler.ProtocolHandler.prototype.processKeyingMessage = function(message) {
        var inCliquesMessage = this._getCliquesMessage(mpenc.utils.clone(message));
        var inAskeMessage = this._getAskeMessage(mpenc.utils.clone(message));
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;

        if (message.dest === null || message.dest === '') {
            if (message.intKeys && (message.intKeys.length === message.members.length)) {
                this.cliquesMember.downflow(inCliquesMessage);
            }
            if (message.nonces && (message.nonces.length === message.members.length)) {
                outAskeMessage = this.askeMember.downflow(inAskeMessage);
            }
            outMessage = this._mergeMessages(null, outAskeMessage);
        } else {
            outCliquesMessage = this.cliquesMember.upflow(inCliquesMessage);
            outAskeMessage = this.askeMember.upflow(inAskeMessage);
            outMessage = this._mergeMessages(outCliquesMessage, outAskeMessage);;
        }
        return outMessage;
    };


    /**
     * Merges the contents of the messages for ASKE and CLIQUES into one message..
     *
     * @method
     * @param cliquesMessage
     *     Message from CLIQUES protocol workflow.
     * @param askeMessage
     *     Message from ASKE protocol workflow.
     * @returns {ProtocolMessage}
     *     Joined message (not wire encoded).
     */
    mpenc.handler.ProtocolHandler.prototype._mergeMessages = function(cliquesMessage,
                                                                      askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = mpenc.handler.ProtocolMessage(this.id);

        if (cliquesMessage && askeMessage) {
            _assert(cliquesMessage.source === askeMessage.source,
                    "Message source mismatch, this shouldn't happen.");
            _assert(cliquesMessage.dest === askeMessage.dest,
                    "Message destination mismatch, this shouldn't happen.");
        }

        // Empty objects to simplify further logic.
        cliquesMessage = cliquesMessage || {};
        askeMessage = askeMessage || {};

        newMessage.dest = cliquesMessage.dest || askeMessage.dest || '';
        newMessage.flow = cliquesMessage.flow || askeMessage.flow;
        newMessage.members = cliquesMessage.members || askeMessage.members;
        newMessage.intKeys = cliquesMessage.intKeys || null;
        newMessage.debugKeys = cliquesMessage.debugKeys || null;
        newMessage.nonces = askeMessage.nonces || null;
        newMessage.pubKeys = askeMessage.pubKeys || null;
        newMessage.sessionSignature = askeMessage.sessionSignature || null;
        if (cliquesMessage.agreement === 'ika') {
            newMessage.agreement = 'initial';
        } else {
            newMessage.agreement = 'auxilliary';
        }

        return newMessage;
    };


    /**
     * Extracts a CLIQUES message out of the received protocol handler message.
     *
     * @method
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.cliques.CliquesMessage}
     *     Extracted message.
     */
    mpenc.handler.ProtocolHandler.prototype._getCliquesMessage = function(message) {
        var newMessage = mpenc.cliques.CliquesMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.flow = message.flow;
        newMessage.members = message.members;
        newMessage.intKeys = message.intKeys;
        newMessage.debugKeys = message.debugKeys;
        if (message.agreement === 'initial') {
            newMessage.agreement = 'ika';
        } else {
            newMessage.agreement = 'aka';
        }

        return newMessage;
    };


    /**
     * Extracts a ASKE message out of the received protocol handler message.
     *
     * @method
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    mpenc.handler.ProtocolHandler.prototype._getAskeMessage = function(message) {
        var newMessage = mpenc.ske.SignatureKeyExchangeMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.flow = message.flow;
        newMessage.members = message.members;
        newMessage.nonces = message.nonces;
        newMessage.pubKeys = message.pubKeys;
        newMessage.sessionSignature = message.sessionSignature;

        return newMessage;
    };
})();
