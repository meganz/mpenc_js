/**
 * @fileOverview
 * Implementation of a protocol handler with its state machine.
 */

define([
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "mpenc/greet/cliques",
    "mpenc/greet/ske",
    "mpenc/codec",
    "mpenc/messages",
], function(assert, utils, cliques, ske, codec, messages) {
    "use strict";

    /**
     * @exports mpenc/handler
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
    var ns = {};

    var _assert = assert.assert;

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
     * "Enumeration" defining the different stable and intermediate states of
     * the mpENC module.
     *
     * @property NULL {integer}
     *     Uninitialised (default) state.
     * @property INIT_UPFLOW {integer}
     *     During process of initial protocol upflow.
     * @property INIT_DOWNFLOW {integer}
     *     During process of initial protocol downflow.
     * @property INITIALISED {integer}
     *     Default state during general usage of mpENC. No protocol/key
     *     negotiation going on, and a valid group key is available.
     * @property AUX_UPFLOW {integer}
     *     During process of auxiliary protocol upflow.
     * @property AUX_DOWNFLOW {integer}
     *     During process of auxiliary protocol downflow.
     */
    ns.STATE = {
        NULL:          0x00,
        INIT_UPFLOW:   0x01,
        INIT_DOWNFLOW: 0x02,
        INITIALISED:   0x03,
        AUX_UPFLOW:    0x04,
        AUX_DOWNFLOW:  0x05,
    };


    /** Default size in bytes for the exponential padding to pad to. */
    ns.DEFAULT_EXPONENTIAL_PADDING = 128;

    /**
     * Implementation of a protocol handler with its state machine.
     *
     * @constructor
     * @param id {string}
     *     Member's identifier string.
     * @param privKey {string}
     *     This participant's static/long term private key.
     * @param pubKey {string}
     *     This participant's static/long term public key.
     * @param staticPubKeyDir {object}
     *     An object with a `get(key)` method, returning the static public key of
     *     indicated by member ID `ky`.
     * @param queueUpdatedCallback {Function}
     *      A callback function, that will be called every time something was
     *      added to `protocolOutQueue`, `messageOutQueue` or `uiQueue`.
     * @param stateUpdatedCallback {Function}
     *      A callback function, that will be called every time the `state` is
     *      changed.
     * @param exponentialPadding {integer}
     *     Number of bytes to pad the cipher text to come out as (0 to turn off
     *     padding). If the clear text will result in a larger cipher text than
     *     exponentialPadding, power of two exponential padding sizes will be
     *     used.
     * @returns {ProtocolHandler}
     *
     * @property id {string}
     *     Member's identifier string.
     * @property privKey {string}
     *     This participant's static/long term private key.
     * @property pubKey {string}
     *     This participant's static/long term public key.
     * @property staticPubKeyDir {object}
     *     An object with a `get(key)` method, returning the static public key of
     *     indicated by member ID `ky`.
     * @property protocolOutQueue {Array}
     *     Queue for outgoing protocol related (non-user) messages, prioritised
     *     in processing over user messages.
     * @property messageOutQueue {Array}
     *     Queue for outgoing user content messages.
     * @property uiQueue {Array}
     *     Queue for messages to display in the UI. Contains objects with
     *     attributes `type` (can be strings 'message', 'info', 'warn' and
     *     'error') and `message`.
     * @property askeMember {SignatureKeyExchangeMember}
     *      Reference to signature key exchange protocol handler with the same
     *      participant ID.
     * @property cliquesMember {CliquesMember}
     *     Reference to CLIQUES protocol handler with the same participant ID.
     * @property state {integer}
     *     Current state of the mpENC protocol handler according to {STATE}.
     * @property exponentialPadding {integer}
     *     Number of bytes to pad the cipher text to come out as (0 to turn off
     *     padding). If the clear text will result in a larger cipher text than
     *     exponentialPadding, power of two exponential padding sizes will be
     *     used.
     */
    ns.ProtocolHandler = function(id, privKey, pubKey, staticPubKeyDir,
                                  queueUpdatedCallback, stateUpdatedCallback,
                                  exponentialPadding) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.protocolOutQueue = [];
        this.messageOutQueue = [];
        this.uiQueue = [];
        this.queueUpdatedCallback = queueUpdatedCallback || function() {};
        this.stateUpdatedCallback = stateUpdatedCallback || function() {};
        this.state = ns.STATE.NULL;
        this.exponentialPadding = exponentialPadding || ns.DEFAULT_EXPONENTIAL_PADDING;

        // Sanity check.
        _assert(this.id && this.privKey && this.pubKey && this.staticPubKeyDir,
                'Constructor call missing required parameters.');

        // Make protocol handlers for sub tasks.
        this.cliquesMember = new cliques.CliquesMember(this.id);
        this.askeMember = new ske.SignatureKeyExchangeMember(this.id);
        this.askeMember.staticPrivKey = privKey;
        this.askeMember.staticPubKeyDir = staticPubKeyDir;

        return this;
    };


    /**
     * Mechanism to start the protocol negotiation with the group participants..
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     * @returns {mpenc.messages.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._start = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        return this._mergeMessages(cliquesMessage, askeMessage);
    };


    /**
     * Start the protocol negotiation with the group participants..
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     */
    ns.ProtocolHandler.prototype.start = function(otherMembers) {
        _assert(this.state === ns.STATE.NULL,
                'start() can only be called from an uninitialised state.');
        this.state = ns.STATE.INIT_UPFLOW;
        this.stateUpdatedCallback(this);

        var outContent = this._start(otherMembers);
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }
    };


    /**
     * Mechanism to start a new upflow for joining new members..
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     * @returns {mpenc.messages.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._join = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        return this._mergeMessages(cliquesMessage, askeMessage);
    };


    /**
     * Start a new upflow for joining new members..
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     */
    ns.ProtocolHandler.prototype.join = function(newMembers) {
        _assert(this.state === ns.STATE.INITIALISED,
                'join() can only be called from an initialised state.');
        this.state = ns.STATE.AUX_UPFLOW;
        this.stateUpdatedCallback(this);

        var outContent = this._join(newMembers);
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }
    };


    /**
     * Mechanism to start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     * @returns {mpenc.messages.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._exclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        return this._mergeMessages(cliquesMessage, askeMessage);
    };


    /**
     * Start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     */
    ns.ProtocolHandler.prototype.exclude = function(excludeMembers) {
        _assert(this.state === ns.STATE.INITIALISED,
                'exclude() can only be called from an initialised state.');
        this.state = ns.STATE.AUX_DOWNFLOW;
        this.stateUpdatedCallback(this);

        var outContent = this._exclude(excludeMembers);
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }

        if (this.askeMember.isSessionAcknowledged()) {
            this.state = ns.STATE.INITIALISED;
            this.stateUpdatedCallback(this);
        }
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @returns {mpenc.messages.ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    ns.ProtocolHandler.prototype._quit = function() {
        _assert(this.askeMember.ephemeralPrivKey !== null,
                'Not participating.');
        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();
        return this._mergeMessages(null, askeMessage);
    };


    /**
     * Start the downflow for quitting participation.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.quit = function() {
        _assert(this.state === ns.STATE.INITIALISED,
                'quit() can only be called from an initialised state.');
        this.state = ns.STATE.NULL;
        this.stateUpdatedCallback(this);

        var outContent = this._quit();
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }
    };


    /**
     * Mechanism to refresh group key.
     *
     * @returns {mpenc.messages.ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    ns.ProtocolHandler.prototype._refresh = function() {
        var cliquesMessage = this.cliquesMember.akaRefresh();
        return this._mergeMessages(cliquesMessage, null);
    };


    /**
     * Refresh group key.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.refresh = function() {
        _assert((this.state === ns.STATE.INITIALISED)
                || (this.state === ns.STATE.INIT_DOWNFLOW)
                || (this.state === ns.STATE.AUX_DOWNFLOW),
                'refresh() can only be called from an initialised or downflow states.');
        this.state = ns.STATE.INITIALISED;
        this.stateUpdatedCallback(this);

        var outContent = this._refresh();
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }
    };


    /**
     * Fully re-run whole key agreements, but retain the ephemeral signing key.
     *
     * @param keepMembers {Array}
     *     Iterable of members to keep in the group (exclude others). This list
     *     should include the one self. (Optional parameter.)
     * @method
     */
    ns.ProtocolHandler.prototype.fullRefresh = function(keepMembers) {
        this.state = ns.STATE.INIT_UPFLOW;
        this.stateUpdatedCallback(this);

        // Remove ourselves from members list to keep (if we're in there).
        var otherMembers = utils.clone(this.cliquesMember.members);
        if (keepMembers) {
            otherMembers = utils.clone(keepMembers);
        }
        var myPos = otherMembers.indexOf(this.id);
        if (myPos >= 0) {
            otherMembers.splice(myPos, 1);
        }

        // Now start a normal upflow for an initial agreement.
        var outContent = this._start(otherMembers);
        if (outContent) {
            var outMessage = {
                from: this.id,
                to: outContent.dest,
                message: codec.encodeMessage(outContent, null,
                                             this.askeMember.ephemeralPrivKey,
                                             this.askeMember.ephemeralPubKey),
            };
            this.protocolOutQueue.push(outMessage);
            this.queueUpdatedCallback(this);
        }
    };


    /**
     * Recover from protocol failure.
     *
     * An attempt is made to do so with as little protocol overhead as possible.
     *
     * @param keepMembers {Array}
     *     Iterable of members to keep in the group (exclude others). This list
     *     should include the one self. (Optional parameter.)
     * @method
     */
    ns.ProtocolHandler.prototype.recover = function(keepMembers) {
        var toKeep = [];
        var toExclude = [];

        if (keepMembers && (keepMembers.length > 0)) {
            // Sort through keepMembers (they may be in "odd" order).
            for (var i = 0; i < this.askeMember.members.length; i++) {
                var index = keepMembers.indexOf(this.askeMember.members[i]);
                if (index < 0) {
                    toExclude.push(this.askeMember.members[i]);
                } else {
                    toKeep.push(this.askeMember.members[i]);
                }
            }
            _assert(toKeep.length === keepMembers.length,
                    'Mismatch between members to keep and current members.');
        }

        if (toExclude.length > 0) {
            this.state = ns.STATE.AUX_DOWNFLOW;
            this.stateUpdatedCallback(this);

            var outContent = this._exclude(toExclude);
            if (outContent) {
                var outMessage = {
                    from: this.id,
                    to: outContent.dest,
                    message: codec.encodeMessage(outContent, null,
                                                 this.askeMember.ephemeralPrivKey,
                                                 this.askeMember.ephemeralPubKey),
                };
                this.protocolOutQueue.push(outMessage);
                this.queueUpdatedCallback(this);
            }
        } else {
            if (this.askeMember.isSessionAcknowledged() &&
                    ((this.state === ns.STATE.INITIALISED)
                            || (this.state === ns.STATE.INIT_DOWNFLOW)
                            || (this.state === ns.STATE.AUX_DOWNFLOW))) {
                this.refresh();
            } else {
                this.fullRefresh((toKeep.length > 0) ? toKeep : undefined);
            }
        }
    };


    /**
     * Handles mpENC protocol message processing.
     *
     * @method
     * @param wireMessage {object}
     *     Received message (wire encoded). The message contains an attribute
     *     `message` carrying either an {@link mpenc.messages.ProtocolMessage}
     *     or {@link mpenc.messages.DataMessage} payload.
     */
    ns.ProtocolHandler.prototype.processMessage = function(wireMessage) {
        var classify = codec.categoriseMessage(wireMessage.message);

        if (!classify) {
            return;
        }

        switch (classify.category) {
            case codec.MESSAGE_CATEGORY.MPENC_ERROR:
                this.uiQueue.push({
                    type: 'error',
                    message: 'Error in mpENC protocol: ' + classify.content
                });
                this.queueUpdatedCallback(this);
                break;
            case codec.MESSAGE_CATEGORY.PLAIN:
                var outMessage = {
                    from: this.id,
                    to: wireMessage.from,
                    message: codec.getQueryMessage(
                        "We're not dealing with plaintext messages. Let's negotiate mpENC communication."),
                };
                this.protocolOutQueue.push(outMessage);;
                wireMessage.type = 'info';
                wireMessage.message = 'Received unencrypted message, requesting encryption.';
                this.uiQueue.push(wireMessage);
                this.queueUpdatedCallback(this);
                break;
            case codec.MESSAGE_CATEGORY.MPENC_QUERY:
                // Initiate keying protocol flow.
                this.start(wireMessage.from);
                break;
            case codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE:
                var decodedMessage = null;
                if (this.cliquesMember.groupKey) {
                    // In case of a key refresh (groupKey existent),
                    // the signing pubKeys won't be part of the message.
                    var signingPubKey = this.askeMember.getMemberEphemeralPubKey(wireMessage.from);
                    decodedMessage = codec.decodeMessageContent(classify.content,
                                                                this.cliquesMember.groupKey.substring(0, 16),
                                                                signingPubKey);
                } else {
                    decodedMessage = codec.decodeMessageContent(classify.content);
                }

                // This is an mpenc.greet message.
                var keyingMessageResult = this._processKeyingMessage(decodedMessage);
                var outContent = keyingMessageResult.decodedMessage;

                if (outContent) {
                    var outMessage = {
                        from: this.id,
                        to: outContent.dest,
                        message: codec.encodeMessage(outContent, null,
                                                     this.askeMember.ephemeralPrivKey,
                                                     this.askeMember.ephemeralPubKey),
                    };
                    this.protocolOutQueue.push(outMessage);
                    this.queueUpdatedCallback(this);
                } else {
                    // Nothing to do, we're done here.
                }
                if(keyingMessageResult.newState) {
                    // Update the state if required.
                    this.state = keyingMessageResult.newState;
                    this.stateUpdatedCallback(this);
                }
                break;
            case codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE:
                var decodedMessage = null;
                _assert(this.state === ns.STATE.INITIALISED,
                        'Data messages can only be decrypted from an initialised state.');

                // Let's crack this baby open.
                var signingPubKey = this.askeMember.getMemberEphemeralPubKey(wireMessage.from);
                decodedMessage = codec.decodeMessageContent(classify.content,
                                                            this.cliquesMember.groupKey.substring(0, 16),
                                                            signingPubKey);

                if (decodedMessage.signatureOk === false) {
                    // Signature failed, abort!
                    wireMessage.type = 'error';
                    wireMessage.message = 'Signature of received message invalid.';
                    this.uiQueue.push(wireMessage);
                } else {
                    wireMessage.type = 'message';
                    wireMessage.message = decodedMessage.data;
                    this.uiQueue.push(wireMessage);
                }
                this.queueUpdatedCallback(this);
                break;
            default:
                _assert(false, 'Received unknown message category: ' + classify.category);
                break;
        }
    };


    /**
     * Sends a message confidentially to the current group.
     *
     * @method
     * @param messageContent {string}
     *     Unencrypted message content to be sent (plain text or HTML).
     * @param metadata {*}
     *     Use this argument to pass additional meta-data to be used later in
     *     plain text (unencrypted) in the implementation.
     */
    ns.ProtocolHandler.prototype.send = function(messageContent, metadata) {
        _assert(this.state === ns.STATE.INITIALISED,
                'Messages can only be sent in initialised state.');
        var outMessage = {
            from: this.id,
            to: '',
            metadata: metadata,
            message: codec.encodeMessage(messageContent,
                                         this.cliquesMember.groupKey.substring(0, 16),
                                         this.askeMember.ephemeralPrivKey,
                                         this.askeMember.ephemeralPubKey,
                                         this.exponentialPadding),
        };
        this.messageOutQueue.push(outMessage);
        this.queueUpdatedCallback(this);
    };


    /**
     * Sends a message confidentially to an individual participant.
     *
     * *Warning:*
     *
     * A directed message is sent to one recipient only *to avoid network
     * traffic.* For the current implementation, from a protection point of
     * view the message has to be considered public in a group communication
     * context. This means, that this mechanism is unsuitable for exchanging
     * conversation transcripts with group participants in the presence of
     * participants who are not entitled to *all* messages within the
     * transcript!
     *
     * @method
     * @param messageContent {string}
     *     Unencrypted message content to be sent (plain text or HTML).
     * @param to {string}
     *     Recipient of a directed message (optional, default is to send to
     *     entire group). *Note:* See warning on confidentiality above!
     * @param metadata {*}
     *     Use this argument to pass additional meta-data to be used later in
     *     plain text (unencrypted) in the implementation.
     */
    ns.ProtocolHandler.prototype.sendTo = function(messageContent, to, metadata) {
        _assert(this.state === ns.STATE.INITIALISED,
                'Messages can only be sent in initialised state.');
        _assert(to && (to.length > 0),
                'A recipient has to be given.');
        var outMessage = {
            from: this.id,
            to: to,
            metadata: metadata,
            message: codec.encodeMessage(messageContent,
                                         this.cliquesMember.groupKey.substring(0, 16),
                                         this.askeMember.ephemeralPrivKey,
                                         this.askeMember.ephemeralPubKey,
                                         this.exponentialPadding),
        };
        this.messageOutQueue.push(outMessage);
        this.queueUpdatedCallback(this);
    };


    /**
     * Sends an mpENC protocol error message to the current group.
     *
     * @method
     * @param messageContent {string}
     *     Error message content to be sent.
     */
    ns.ProtocolHandler.prototype.sendError = function(messageContent) {
        var outMessage = {
            from: this.id,
            to: '',
            message: codec.getErrorMessage(messageContent),
        };
        this.protocolOutQueue.push(outMessage);
        this.queueUpdatedCallback(this);
    };


    /**
     * Handles keying protocol execution with all participants.
     *
     * @method
     * @param message {mpenc.messages.ProtocolMessage}
     *     Received message (decoded). See {@link mpenc.messages.ProtocolMessage}.
     * @returns {object}
     *     Object containing the decoded message content as
     *     {mpenc.messages.ProtocolMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the ProtocolHandler state in
     *     attribute `newState`.
     */
    ns.ProtocolHandler.prototype._processKeyingMessage = function(message) {
        var inCliquesMessage = this._getCliquesMessage(utils.clone(message));
        var inAskeMessage = this._getAskeMessage(utils.clone(message));
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;
        var newState = null;

        if (message.dest === null || message.dest === '') {
            // Dealing with a broadcast downflow message.
            // Check for legal state transitions.
            if (message.agreement === 'initial') {
                _assert((this.state === ns.STATE.INIT_UPFLOW)
                        || (this.state === ns.STATE.INIT_DOWNFLOW)
                        || (this.state === ns.STATE.INITIALISED),
                        'Initial downflow can only follow an initial upflow (or own downflow).');
            } else {
                _assert((this.state === ns.STATE.INITIALISED)
                        || (this.state === ns.STATE.AUX_UPFLOW)
                        || (this.state === ns.STATE.AUX_DOWNFLOW),
                        'Auxiliary downflow can only follow an initialised state or auxiliary upflow (or own downflow).');
            }
            if (message.signingKey) {
                // Sender is quitting participation.
                // TODO: quit() stuff here: CLIQUES will need to refresh keys, but avoid a race condition if all do it.
                _assert(false, 'Key refresh for quitting is not implemented, yet!');
            } else {
                // Content for the CLIQUES protocol.
                if (message.intKeys && (message.intKeys.length === message.members.length)) {
                    this.cliquesMember.downflow(inCliquesMessage);
                }
                // Content for the signature key exchange protocol.
                if (message.nonces && (message.nonces.length === message.members.length)) {
                    outAskeMessage = this.askeMember.downflow(inAskeMessage);
                }
            }
            outMessage = this._mergeMessages(null, outAskeMessage);
            if (outMessage && message.agreement === 'initial') {
                // Can't be inferred from ASKE message alone.
                outMessage.agreement = 'initial';
            }
            // Handle state transitions.
            if (outMessage) {
                if (outMessage.agreement === 'initial') {
                    newState = ns.STATE.INIT_DOWNFLOW;
                } else {
                    newState = ns.STATE.AUX_DOWNFLOW;
                }
            }
            if (this.askeMember.isSessionAcknowledged()) {
                // We have seen and verified all broadcasts from others.
                newState = ns.STATE.INITIALISED;
            }
        } else {
            // Dealing with a directed upflow message.
            // Check for legal state transitions.
            _assert((this.state === ns.STATE.INITIALISED)
                    || (this.state === ns.STATE.NULL),
                    'Auxiliary upflow can only follow an uninitialised or initialised state.');
            outCliquesMessage = this.cliquesMember.upflow(inCliquesMessage);
            outAskeMessage = this.askeMember.upflow(inAskeMessage);
            outMessage = this._mergeMessages(outCliquesMessage, outAskeMessage);
            // Handle state transitions.
            if (message.agreement === 'initial') {
                if (outMessage.dest === '') {
                    newState = ns.STATE.INIT_DOWNFLOW;
                } else {
                    newState = ns.STATE.INIT_UPFLOW;
                }
            } else {
                if (outMessage.dest === '') {
                    newState = ns.STATE.AUX_DOWNFLOW;
                } else {
                    newState = ns.STATE.AUX_UPFLOW;
                }
            }
        }
        return { decodedMessage: outMessage,
                 newState: newState };
    };


    /**
     * Merges the contents of the messages for ASKE and CLIQUES into one message..
     *
     * @method
     * @param cliquesMessage {mpenc.greet.cliques.CliquesMessage}
     *     Message from CLIQUES protocol workflow.
     * @param askeMessage {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Message from ASKE protocol workflow.
     * @returns {mpenc.messages.ProtocolMessage}
     *     Joined message (not wire encoded).
     */
    ns.ProtocolHandler.prototype._mergeMessages = function(cliquesMessage,
                                                           askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = new messages.ProtocolMessage(this.id);

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
        newMessage.signingKey = askeMessage.signingKey || null;
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
     * @param message {mpenc.messages.ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.cliques.CliquesMessage}
     *     Extracted message.
     */
    ns.ProtocolHandler.prototype._getCliquesMessage = function(message) {
        var newMessage = cliques.CliquesMessage(this.id);
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
     * @param message {mpenc.greet.messages.ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    ns.ProtocolHandler.prototype._getAskeMessage = function(message) {
        var newMessage = ske.SignatureKeyExchangeMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.flow = message.flow;
        newMessage.members = message.members;
        newMessage.nonces = message.nonces;
        newMessage.pubKeys = message.pubKeys;
        newMessage.sessionSignature = message.sessionSignature;
        newMessage.signingKey = message.signingKey;

        return newMessage;
    };


    return ns;
});
