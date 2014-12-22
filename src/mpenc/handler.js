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
], function(assert, utils, cliques, ske, codec) {
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
     * @property READY {integer}
     *     Default state during general usage of mpENC. No protocol/key
     *     negotiation going on, and a valid group key is available.
     * @property AUX_UPFLOW {integer}
     *     During process of auxiliary protocol upflow.
     * @property AUX_DOWNFLOW {integer}
     *     During process of auxiliary protocol downflow.
     * @property QUIT {integer}
     *     After quitting participation.
     */
    ns.STATE = {
        NULL:          0x00,
        INIT_UPFLOW:   0x01,
        INIT_DOWNFLOW: 0x02,
        READY:   0x03,
        AUX_UPFLOW:    0x04,
        AUX_DOWNFLOW:  0x05,
        QUIT:          0x06,
    };

    // Add reverse mapping to string representation.
    var _STATE_MAPPING = {};
    for (var propName in ns.STATE) {
        _STATE_MAPPING[ns.STATE[propName]] = propName;
    }


    /**
     * "Enumeration" defining the different mpENC error message severities.
     *
     * @property INFO {integer}
     *     An informational message with no or very low severity.
     * @property WARNING {integer}
     *     An warning message.
     * @property ERROR {integer}
     *     An error message with high severity.
     * @property TERMINAL {integer}
     *     A terminal error message that demands the immediate termination of
     *     all protocol execution. It should be followed by each participant's
     *     immediate invocation of a quit protocol flow.
     */
    ns.ERROR = {
        INFO:          0x00,
        WARNING:       0x01,
        TERMINAL:      0x02
    };

    // Add reverse mapping to string representation.
    var _ERROR_MAPPING = {};
    for (var propName in ns.ERROR) {
        _ERROR_MAPPING[ns.ERROR[propName]] = propName;
    }


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
     * @property recovering {bool}
     *     `true` if in recovery mode state, usually `false`.
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
        this.recovering = false;
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
     * Mechanism to start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     * @returns {mpenc.codec.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._start = function(otherMembers) {
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.messageType = codec.MESSAGE_TYPE.RECOVER_INIT_INITIATOR_UP;
        } else {
            protocolMessage.messageType = codec.MESSAGE_TYPE.INIT_INITIATOR_UP;
        }
        return protocolMessage;
    };


    /**
     * Start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     */
    ns.ProtocolHandler.prototype.start = function(otherMembers) {
        _assert(this.state === ns.STATE.NULL,
                'start() can only be called from an uninitialised state.');
        utils.dummyLogger('DEBUG', 'Invoking initial START flow operation.');
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
     * Mechanism to start a new upflow for joining new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     * @returns {mpenc.codec.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._join = function(newMembers) {
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        protocolMessage.messageType = codec.MESSAGE_TYPE.JOIN_AUX_INITIATOR_UP;
        return protocolMessage;
    };


    /**
     * Start a new upflow for joining new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     */
    ns.ProtocolHandler.prototype.join = function(newMembers) {
        _assert(this.state === ns.STATE.READY,
                'join() can only be called from a ready state.');
        utils.dummyLogger('DEBUG', 'Invoking JOIN flow operation.');
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
     * @returns {mpenc.codec.ProtocolMessage}
     *     Un-encoded message content.
     */
    ns.ProtocolHandler.prototype._exclude = function(excludeMembers) {
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.messageType = codec.MESSAGE_TYPE.RECOVER_EXCLUDE_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.messageType = codec.MESSAGE_TYPE.EXCLUDE_AUX_INITIATOR_DOWN;
        }

        return protocolMessage;
    };


    /**
     * Start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     */
    ns.ProtocolHandler.prototype.exclude = function(excludeMembers) {
        if (this.recovering) {
            _assert((this.state === ns.STATE.INIT_DOWNFLOW)
                    || (this.state === ns.STATE.AUX_DOWNFLOW),
                    'exclude() for recovery can only be called from a ready or downflow state.');
        } else {
            _assert(this.state === ns.STATE.READY,
                    'exclude() can only be called from a ready state.');
        }
        utils.dummyLogger('DEBUG', 'Invoking EXCLUDE flow operation.');
        this.state = ns.STATE.AUX_DOWNFLOW;
        this.stateUpdatedCallback(this);

        var outContent = this._exclude(excludeMembers);
        if (outContent.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
            return;
        }

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
            this.state = ns.STATE.READY;
            this.recovering = false;
            this.stateUpdatedCallback(this);
        }
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @returns {mpenc.codec.ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    ns.ProtocolHandler.prototype._quit = function() {
        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();

        var protocolMessage = this._mergeMessages(null, askeMessage);
        protocolMessage.messageType = codec.MESSAGE_TYPE.QUIT_DOWN;
        return protocolMessage;
    };


    /**
     * Start the downflow for quitting participation.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.quit = function() {
        if (this.state === ns.STATE.QUIT) {
            // Nothing do do here.
            return;
        }
        _assert(this.askeMember.ephemeralPrivKey !== null,
                'Not participating.');
        utils.dummyLogger('DEBUG',
                          'Invoking QUIT request containing private signing key.');
        this.state = ns.STATE.QUIT;
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
     * @returns {mpenc.codec.ProtocolMessage}
     *     Un-encoded message content.
     * @method
     */
    ns.ProtocolHandler.prototype._refresh = function() {
        var cliquesMessage = this.cliquesMember.akaRefresh();

        var protocolMessage = this._mergeMessages(cliquesMessage, null);
        if (this.recovering) {
            protocolMessage.messageType = codec.MESSAGE_TYPE.RECOVER_REFRESH_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.messageType = codec.MESSAGE_TYPE.REFRESH_AUX_INITIATOR_DOWN;
        }
        return protocolMessage;
    };


    /**
     * Refresh group key.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.refresh = function() {
        _assert((this.state === ns.STATE.READY)
                || (this.state === ns.STATE.INIT_DOWNFLOW)
                || (this.state === ns.STATE.AUX_DOWNFLOW),
                'refresh() can only be called from a ready or downflow states.');
        utils.dummyLogger('DEBUG', 'Invoking REFRESH flow operation.');
        this.state = ns.STATE.READY;
        this.refreshing = false;
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
        if (outContent.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
            return;
        }

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
        utils.dummyLogger('DEBUG', 'Invoking RECOVER flow operation.');
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

        this.recovering = true;
        if ((this.state === ns.STATE.READY)
                || (this.state === ns.STATE.INIT_DOWNFLOW)
                || (this.state === ns.STATE.AUX_DOWNFLOW)) {
            if (toExclude.length > 0) {
                this.askeMember.discardAuthentications();
                this.exclude(toExclude);
            } else {
                // TODO: Check, whether this would only work for isSessionAcknowledged(),
                //       or whether we need a fourth case to re-ack all participants.
                this.refresh();
            }
        } else {
            this.askeMember.discardAuthentications();
            this.fullRefresh((toKeep.length > 0) ? toKeep : undefined);
        }
    };


    /**
     * Handles mpENC protocol message processing.
     *
     * @method
     * @param wireMessage {object}
     *     Received message (wire encoded). The message contains an attribute
     *     `message` carrying either an {@link mpenc.codec.ProtocolMessage}
     *     or {@link mpenc.codec.DataMessage} payload.
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
                    if ((wireMessage.from === this.id) && (!signingPubKey)) {
                        utils.dummyLogger('DEBUG',
                                          'Using own ephemeral signing pub key, not taken from list.');
                        signingPubKey = this.askeMember.ephemeralPubKey;
                    }
                    decodedMessage = codec.decodeMessageContent(classify.content,
                                                                this.cliquesMember.groupKey.substring(0, 16),
                                                                signingPubKey);
                } else {
                    decodedMessage = codec.decodeMessageContent(classify.content);
                }

                // This is an mpenc.greet message.
                var oldState = this.state;
                var keyingMessageResult = this._processKeyingMessage(decodedMessage);
                if (keyingMessageResult === null) {
                    return;
                }
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
                if(keyingMessageResult.newState &&
                        (keyingMessageResult.newState !== oldState)) {
                    // Update the state if required.
                    utils.dummyLogger('DEBUG',
                                      'Reached new state: '
                                      + _STATE_MAPPING[keyingMessageResult.newState]);
                    this.state = keyingMessageResult.newState;
                    this.stateUpdatedCallback(this);
                }
                break;
            case codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE:
                var decodedMessage = null;
                _assert(this.state === ns.STATE.READY,
                        'Data messages can only be decrypted from a ready state.');

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
     * Inspects a message for its type and some meta-data.
     *
     * This is a "cheap" operation, that is not performing any cryptographic
     * operations, but only looks at the components of the message payload.
     *
     * @method
     * @param wireMessage {object}
     *     Received message (wire encoded). The message contains an attribute
     *     `message` carrying either an {@link mpenc.codec.ProtocolMessage}
     *     or {@link mpenc.codec.DataMessage} payload.
     * @returns {object}
     *     Message meta-data.
     */
    ns.ProtocolHandler.prototype.inspectMessage = function(wireMessage) {
        var classify = codec.categoriseMessage(wireMessage.message);
        var result = {};

        switch (classify.category) {
            case codec.MESSAGE_CATEGORY.PLAIN:
                result.type = 'plain';
                break;
            case codec.MESSAGE_CATEGORY.MPENC_QUERY:
                result.type = 'mpENC query';
                break;
            case codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE:
                result = codec.inspectMessageContent(classify.content);

                // Complete the origin attribute with further knowledge.
                if (result.origin === '???') {
                    if (this.askeMember.members.indexOf(result.from) >= 0) {
                        if (result.isInitiator()) {
                            result.origin = 'initiator';
                        } else {
                            result.origin = 'participant';
                        }
                    } else {
                        result.origin = 'outsider';
                    }
                }
                if (result.from === this.id) {
                    result.origin += ' (self)';
                }

                break;
            case codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE:
                result.type = 'mpENC data message';
                break;
            case codec.MESSAGE_CATEGORY.MPENC_ERROR:
                result.type = 'mpENC error';
                break;
            default:
                // Ignoring all others.
                break;
        }

        return result;
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
        _assert(this.state === ns.STATE.READY,
                'Messages can only be sent in ready state.');
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
        _assert(this.state === ns.STATE.READY,
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
     * @param severity {integer}
     *     Severity of the error.  One of `mpenc.handler.ERROR`.
     * @param messageContent {string}
     *     Error message content to be sent.
     */
    ns.ProtocolHandler.prototype.sendError = function(severity, messageContent) {
        var severityString = _ERROR_MAPPING[severity];
        if (severityString === undefined) {
            throw new Error('Illegal error severity: ' + severity + '.');
        }

        var textMessage = severityString + ': ' + messageContent;
        var outMessage = {
            from: this.id,
            to: '',
            message: codec.encodeErrorMessage(this.id,
                                              _ERROR_MAPPING[severity],
                                              messageContent,
                                              this.askeMember.ephemeralPrivKey,
                                              this.askeMember.ephemeralPubKey),
        };
        this.protocolOutQueue.push(outMessage);
        this.queueUpdatedCallback(this);

        if (severity === ns.ERROR.TERMINAL) {
            this.quit();
        }
    };


    /**
     * Handles keying protocol execution with all participants.
     *
     * @method
     * @param message {mpenc.codec.ProtocolMessage}
     *     Received message (decoded). See {@link mpenc.codec.ProtocolMessage}.
     * @returns {object}
     *     Object containing the decoded message content as
     *     {mpenc.codec.ProtocolMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the ProtocolHandler state in
     *     attribute `newState`.
     */
    ns.ProtocolHandler.prototype._processKeyingMessage = function(message) {
        utils.dummyLogger('DEBUG',
                          'Processing message of type '
                          + message.getMessageTypeString());
        if (this.state === ns.STATE.QUIT) {
            // We're not par of this session, get out of here.
            utils.dummyLogger('DEBUG', "Ignoring message as we're in state QUIT.");
            return null;
        }

        // If I'm not part of it any more, go and quit.
        if (message.members && (message.members.length > 0)
                && (message.members.indexOf(this.id) === -1)) {
            this.quit();
            return null;
        }

        // Ignore the message if it is not for me.
        if ((message.dest !== '') && (message.dest !== this.id)) {
            return null;
        }

        // Ignore the message if it is from me.
        if (message.source === this.id) {
            return null;
        }

        // State transitions.
        if (message.isRecover()) {
            // We're getting this message as part of a recovery flow.
            this.recovering = true;
            // In case of an upflow, we must also discard session authentications.
            if (!message.isDownflow()) {
                this.askeMember.discardAuthentications();
            }
        }

        var inCliquesMessage = this._getCliquesMessage(message);
        var inAskeMessage = this._getAskeMessage(message);
        var outCliquesMessage = null;
        var outAskeMessage = null;
        var outMessage = null;
        var newState = null;

        // Three cases: QUIT, upflow or downflow message.
        if (message.messageType === codec.MESSAGE_TYPE.QUIT_DOWN) {
            // QUIT message.
            _assert(message.signingKey,
                    'Inconsistent message content with message type (signingKey).');
            // Sender is quitting participation.
            this.askeMember.oldEphemeralKeys[message.source] = {
                    priv: message.signingKey,
                    pub:  this.askeMember.ephemeralPubKeys[message.source]
            };
        } else if (message.isDownflow()) {
            // Downflow message.
            if (message.isGKA()) {
                this.cliquesMember.downflow(inCliquesMessage);
            }
            if (message.isSKE()) {
                try {
                    outAskeMessage = this.askeMember.downflow(inAskeMessage);
                } catch (e) {
                    if (e.message.lastIndexOf('Session authentication by member') === 0) {
                        this.sendError(ns.ERROR.TERMINAL, e.message);
                        return null;
                    } else {
                        throw e;
                    }
                }
            }
            outMessage = this._mergeMessages(null, outAskeMessage);
            if (outMessage) {
                outMessage.messageType = message.messageType;
                // In case we're receiving it from an initiator.
                outMessage.clearInitiator(true);
                // Confirmations (subsequent) downflow messages don't have a GKA.
                outMessage.clearGKA();
                // Handle state transitions.
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_DOWNFLOW;
                } else {
                    newState = ns.STATE.INIT_DOWNFLOW;
                }
            }
        } else {
            // Upflow message.
            outCliquesMessage = this.cliquesMember.upflow(inCliquesMessage);
            outAskeMessage = this.askeMember.upflow(inAskeMessage);
            outMessage = this._mergeMessages(outCliquesMessage, outAskeMessage);
            outMessage.messageType = message.messageType;
            // In case we're receiving it from an initiator.
            outMessage.clearInitiator();
            // Handle state transitions.
            if (outMessage.dest === '') {
                outMessage.setDownflow();
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_DOWNFLOW;
                } else {
                    newState = ns.STATE.INIT_DOWNFLOW;
                }
            } else {
                if (message.isAuxiliary()) {
                    newState = ns.STATE.AUX_UPFLOW;
                } else {
                    newState = ns.STATE.INIT_UPFLOW;
                }
            }
        }

        if (this.askeMember.isSessionAcknowledged()) {
            // We have seen and verified all broadcasts from others.
            newState = ns.STATE.READY;
            utils.dummyLogger('DEBUG', 'Reached READY state.');
            this.recovering = false;
        }

        if (outMessage) {
            utils.dummyLogger('DEBUG',
                              'Sending message of type '
                              + outMessage.getMessageTypeString());
        } else {
            utils.dummyLogger('DEBUG', 'No message to send.');
        }
        return { decodedMessage: outMessage,
                 newState: newState };
    };


    /**
     * Merges the contents of the messages for ASKE and CLIQUES into one message.
     *
     * @method
     * @param cliquesMessage {mpenc.greet.cliques.CliquesMessage}
     *     Message from CLIQUES protocol workflow.
     * @param askeMessage {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Message from ASKE protocol workflow.
     * @returns {mpenc.codec.ProtocolMessage}
     *     Joined message (not wire encoded).
     */
    ns.ProtocolHandler.prototype._mergeMessages = function(cliquesMessage,
                                                           askeMessage) {
        // Are we done already?
        if (!cliquesMessage && !askeMessage) {
            return null;
        }

        var newMessage = new codec.ProtocolMessage(this.id);

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
        newMessage.members = cliquesMessage.members || askeMessage.members;
        newMessage.intKeys = cliquesMessage.intKeys || null;
        newMessage.debugKeys = cliquesMessage.debugKeys || null;
        newMessage.nonces = askeMessage.nonces || null;
        newMessage.pubKeys = askeMessage.pubKeys || null;
        newMessage.sessionSignature = askeMessage.sessionSignature || null;
        newMessage.signingKey = askeMessage.signingKey || null;

        return newMessage;
    };


    /**
     * Extracts a CLIQUES message out of the received protocol handler message.
     *
     * @method
     * @param message {mpenc.codec.ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.cliques.CliquesMessage}
     *     Extracted message.
     */
    ns.ProtocolHandler.prototype._getCliquesMessage = function(message) {
        var newMessage = cliques.CliquesMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.members = message.members;
        newMessage.intKeys = message.intKeys;
        newMessage.debugKeys = message.debugKeys;

        // Upflow or downflow.
        if (message.isDownflow()) {
            newMessage.flow = 'down';
        } else {
            newMessage.flow = 'up';
        }

        // IKA or AKA.
        if (message.getOperation() === 'START') {
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
     * @param message {mpenc.greet.codec.ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    ns.ProtocolHandler.prototype._getAskeMessage = function(message) {
        var newMessage = ske.SignatureKeyExchangeMessage(this.id);
        newMessage.source = message.source;
        newMessage.dest = message.dest;
        newMessage.members = message.members;
        newMessage.nonces = message.nonces;
        newMessage.pubKeys = message.pubKeys;
        newMessage.sessionSignature = message.sessionSignature;
        newMessage.signingKey = message.signingKey;

        // Upflow or downflow.
        if (message.isDownflow()) {
            newMessage.flow = 'down';
        } else {
            newMessage.flow = 'up';
        }

        return newMessage;
    };


    return ns;
});
