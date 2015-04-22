/*
 * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/helper/assert",
    "mpenc/helper/utils",
    "mpenc/helper/struct",
    "mpenc/greet/greeter",
    "mpenc/codec",
    "mpenc/message",
    "mpenc/greet/keystore",
    "megalogger",
], function(assert, utils, struct, greeter, codec, message, keystore, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/handler
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

    var logger = MegaLogger.getLogger('handler', undefined, 'mpenc');

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
     * An accessor object to "directory", which can be queried to retrieve a
     * public static signing key of a participant ID.
     *
     * @interface
     * @name PubKeyDir
     */

    /**
     * This method performs the actual lookup and returns the public
     * static signing key.
     *
     * @method PubKeyDir#get
     * @param id {string}
     *     Member ID to request the key for.
     * @returns {string}
     *     Requested key as a byte string.
     */


    /**
     * Implementation of a protocol handler with its state machine.
     *
     * @constructor
     * @param id {string}
     *     Member's identifier string.
     * @param name {string}
     *     Name of this handler (e. g. the chat room name).
     * @param privKey {string}
     *     This participant's static/long term private key.
     * @param pubKey {string}
     *     This participant's static/long term public key.
     * @param staticPubKeyDir {PubKeyDir}
     *     Public key directory object. An object with a `get(key)` method,
     *     returning the static public key of indicated by member ID `ky`.
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
     * @property name {string}
     *     Name of this handler (e. g. the chat room name).
     * @property privKey {string}
     *     This participant's static/long term private key.
     * @property pubKey {string}
     *     This participant's static/long term public key.
     * @property protocolOutQueue {Array}
     *     Queue for outgoing protocol related (non-user) messages, prioritised
     *     in processing over user messages.
     * @property messageOutQueue {Array}
     *     Queue for outgoing user content messages.
     * @property uiQueue {Array}
     *     Queue for messages to display in the UI. Contains objects with
     *     attributes `type` (can be strings 'message', 'info', 'warn' and
     *     'error') and `message`.
     * @property sessionKeyStore {mpenc.greet.keystore.KeyStore}
     *     Store for (sub-) session related keys and information.
     * @property greet {mpenc.greet.greeter.GreetWrapper}
     *     A wrapper interfacing to the different greet (key agreement)
     *     protocol objects involved.
     * @property exponentialPadding {integer}
     *     Number of bytes to pad the cipher text to come out as (0 to turn off
     *     padding). If the clear text will result in a larger cipher text than
     *     exponentialPadding, power of two exponential padding sizes will be
     *     used.
     */
    ns.ProtocolHandler = function(id, name, privKey, pubKey, staticPubKeyDir,
                                  queueUpdatedCallback, stateUpdatedCallback,
                                  exponentialPadding) {
        this.id = id;
        this.name = name;
        this.protocolOutQueue = [];
        this.messageOutQueue = [];
        this.uiQueue = [];
        this.queueUpdatedCallback = queueUpdatedCallback || function() {};
        this.stateUpdatedCallback = stateUpdatedCallback || function() {};
        this.exponentialPadding = exponentialPadding || ns.DEFAULT_EXPONENTIAL_PADDING;

        this._messageSecurity = null;
        this._sessionKeyStore = new keystore.KeyStore(name, function() { return 20; });

        // Set up a trial buffer for trial decryption.
        var self = this;
        var decryptTarget = new ns.DecryptTrialTarget(
            function(wireMessage) {
                return self._messageSecurity.decrypt(wireMessage);
            }, this.uiQueue, 100);
        this._tryDecrypt = new struct.TrialBuffer(this.name, decryptTarget, false);

        this.greet = new greeter.GreetWrapper(this.id,
                                              privKey, pubKey,
                                              staticPubKeyDir,
                                              function(greet) { self.stateUpdatedCallback(self); });

        // Sanity check.
        _assert(this.id && privKey && pubKey && staticPubKeyDir && this._sessionKeyStore,
                'Constructor call missing required parameters.');

        return this;
    };

    ns.ProtocolHandler.prototype._newMessageSecurity = function(greet) {
        // TODO(xl): eventually it should be possible to create a new immutable
        // sessionKeyStore directly from the greet, instead of a single mutable
        // store that persists across key changes. see mpenc_py for the general idea
        this._sessionKeyStore.update(greet.getSessionId(),
                                     greet.getMembers(),
                                     greet.getEphemeralPubKeys(),
                                     greet.getGroupKey().substring(0, 16));
        return new message.MessageSecurity(
            greet.getEphemeralPrivKey(),
            greet.getEphemeralPubKey(),
            this._sessionKeyStore)
    };

    ns.ProtocolHandler.prototype._pushGreetMessage = function(outContent) {
        if (outContent) {
            this._pushMessage(outContent.dest,
                greeter.encodeGreetMessage(
                    outContent,
                    this.greet.getEphemeralPrivKey(),
                    this.greet.getEphemeralPubKey()
                )
            );
        }
    };

    ns.ProtocolHandler.prototype._pushMessage = function(to, message) {
        this.protocolOutQueue.push({
            from: this.id,
            to: to,
            message: message
        });
        this.queueUpdatedCallback(this);
    };

    /**
     * Start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     */
    ns.ProtocolHandler.prototype.start = function(otherMembers) {
        logger.debug('Invoking initial START flow operation.');
        this._pushGreetMessage(this.greet.start(otherMembers));
    };


    /**
     * Start a new upflow for joining new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to join the group.
     */
    ns.ProtocolHandler.prototype.join = function(newMembers) {
        logger.debug('Invoking JOIN flow operation.');
        this._pushGreetMessage(this.greet.join(newMembers));
    };


    /**
     * Start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     */
    ns.ProtocolHandler.prototype.exclude = function(excludeMembers) {
        logger.debug('Invoking EXCLUDE flow operation.');

        var outContent = this.greet.exclude(excludeMembers);
        if (outContent.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
            return;
        }
        this._pushGreetMessage(outContent);
        if (this.greet.isSessionAcknowledged()) {
            this._messageSecurity = this._newMessageSecurity(this.greet);
        }
    };


    /**
     * Start the downflow for quitting participation.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.quit = function() {
        logger.debug('Invoking QUIT request containing private signing key.');
        this._pushGreetMessage(this.greet.quit());
    };


    /**
     * Refresh group key.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.refresh = function() {
        logger.debug('Invoking REFRESH flow operation.');
        var outContent = this.greet.refresh();
        this._messageSecurity = this._newMessageSecurity(this.greet);
        this._pushGreetMessage(outContent);
    };


    /**
     * Fully re-run whole key agreements, but retain the ephemeral signing key.
     *
     * @param keepMembers {Array}
     *     Iterable of members to keep in the group (exclude others). This list
     *     should include the one self. (Optional parameter.)
     * @method
     */
    ns.ProtocolHandler.prototype._fullRefresh = function(keepMembers) {
        // Remove ourselves from members list to keep (if we're in there).
        var otherMembers = utils.clone(this.greet.getMembers());
        if (keepMembers) {
            otherMembers = utils.clone(keepMembers);
        }
        var myPos = otherMembers.indexOf(this.id);
        if (myPos >= 0) {
            otherMembers.splice(myPos, 1);
        }

        // This is a bit of a hack, but we're going to get rid of recover()
        // anyways, so don't worry too much about making this clean.
        this.greet.state = greeter.STATE.NULL;
        // Now start a normal upflow for an initial agreement.
        var outContent = this.greet.start(otherMembers);
        if (outContent.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
            return;
        }
        this._pushGreetMessage(outContent);
    };


    /**
     * Recover from protocol failure.
     *
     * An attempt is made to do so with as little protocol overhead as possible.
     *
     * @param keepMembers {Array<string>}
     *     Members to keep in the group (exclude others). This list should
     *     include the one self. (Optional parameter, empty keeps all.)
     * @method
     */
    ns.ProtocolHandler.prototype.recover = function(keepMembers) {
        logger.debug('Invoking RECOVER flow operation.');
        var toKeep = [];
        var toExclude = [];

        if (keepMembers && (keepMembers.length > 0)) {
            // Sort through keepMembers (they may be in "odd" order).
            for (var i = 0; i < this.greet.getMembers().length; i++) {
                var index = keepMembers.indexOf(this.greet.getMembers()[i]);
                if (index < 0) {
                    toExclude.push(this.greet.getMembers()[i]);
                } else {
                    toKeep.push(this.greet.getMembers()[i]);
                }
            }
            _assert(toKeep.length === keepMembers.length,
                    'Mismatch between members to keep and current members.');
        }

        this.greet.recovering = true;
        if ((this.greet.state === greeter.STATE.READY)
                || (this.greet.state === greeter.STATE.INIT_DOWNFLOW)
                || (this.greet.state === greeter.STATE.AUX_DOWNFLOW)) {
            if (toExclude.length > 0) {
                this.greet.discardAuthentications();
                this.exclude(toExclude);
            } else {
                // TODO: Check, whether this would only work for isSessionAcknowledged(),
                //       or whether we need a fourth case to re-ack all participants.
                this.refresh();
            }
        } else {
            this.greet.discardAuthentications();
            this._fullRefresh((toKeep.length > 0) ? toKeep : undefined);
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
                var errorMessageResult = this._processErrorMessage(classify.content);
                var uiMessageString = _ERROR_MAPPING[errorMessageResult.severity];
                if (errorMessageResult.severity === ns.ERROR.TERMINAL) {
                    uiMessageString += ' ERROR';
                }
                uiMessageString += ': ' + errorMessageResult.message;
                this.uiQueue.push({
                    type: 'error',
                    message: uiMessageString
                });
                this.queueUpdatedCallback(this);
                if (errorMessageResult.severity === ns.ERROR.TERMINAL) {
                    this.quit();
                }
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
                try {
                    var oldState = this.greet.state;
                    this.greet.processIncoming(wireMessage.from, classify.content, this._pushGreetMessage.bind(this));
                    var newState = this.greet.state;
                    if (newState !== oldState) {
                        if (newState === greeter.STATE.QUIT) {
                            this.quit();
                        } else if (newState === greeter.STATE.READY) {
                            this._messageSecurity = this._newMessageSecurity(this.greet);
                        }
                    }
                } catch (e) {
                    if (e.message.lastIndexOf('Session authentication by member') === 0) {
                        this.sendError(ns.ERROR.TERMINAL, e.message);
                        return;
                    } else {
                        throw e;
                    }
                }
                break;
            case codec.MESSAGE_CATEGORY.MPENC_DATA_MESSAGE:
                var decodedMessage = null;
                _assert(this.greet.state === greeter.STATE.READY,
                        'Data messages can only be decrypted from a ready state.');

                this._tryDecrypt.trial(wireMessage);
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
                    if (this.greet.getMembers().indexOf(result.from) >= 0) {
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
        _assert(this.greet.state === greeter.STATE.READY,
                'Messages can only be sent in ready state.');
        var outMessage = {
            from: this.id,
            to: '',
            metadata: metadata,
            message: this._messageSecurity.encrypt(messageContent, this.exponentialPadding),
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
        this._pushMessage('', codec.encodeErrorMessage(this.id,
                                              _ERROR_MAPPING[severity],
                                              messageContent,
                                              this.greet.getEphemeralPrivKey(),
                                              this.greet.getEphemeralPubKey()));

        if (severity === ns.ERROR.TERMINAL) {
            this.quit();
        }
    };


    /**
     * Handles error protocol message handling.
     *
     * @method
     * @param content {string}
     *     Received message string without the armouring/leading `?mpENC Error:`.
     * @returns {object}
     *     Object containing the error message content in the attributes `from`
     *     {string}, `severity` {integer}, `signatureOk` {bool} (`true` if
     *     signature verifies) and `message` {string} (message content).
     */
    ns.ProtocolHandler.prototype._processErrorMessage = function(content) {
        var contentParts = content.split(':');
        var signatureString = contentParts[0];
        var result = { from: contentParts[1].split('"')[1],
                       severity: ns.ERROR[contentParts[2]],
                       signatureOk: null,
                       message: contentParts[3] };
        var pubKey = this.greet.getEphemeralPubKey(result.from);
        if ((signatureString.length >= 0) && (pubKey !== undefined)) {
            var cutOffPos = content.indexOf(':');
            var data = content.substring(cutOffPos + 1);
            result.signatureOk = codec.verifyMessageSignature(codec.MESSAGE_CATEGORY.MPENC_ERROR,
                                                              data, signatureString, pubKey);
        }

        return result;
    };



    /**
     * Trial target holding the data structures to accept positively tried
     * messages, as well as implements the interface methods required for
     * the trial process.
     *
     * @constructor
     * @implements {mpenc/helper/struct.TrialTarget}
     * @param sessionKeyStore {mpenc.greet.keystore.KeyStore}
     *     Store for (sub-) session related keys and information.
     * @param outQueue {array}
     *     Output queue to receive successfully trialled parameters (messages).
     * @param maxSize {integer}
     *     Maximum number of elements to be held in trial buffer.
     * @returns {module:mpenc/handler.DecryptTrialTarget}
     * @memberOf! module:mpenc/handler#
     *
     * @property _sessionKeyStore {mpenc.greet.keystore.KeyStore}
     *     Store for (sub-) session related keys and information.
     * @property _outQueue {array}
     *     Output queue to receive successfully trialled parameters (messages).
     * @property _maxSize {integer}
     *     Maximum number of elements to be held in trial buffer.
     */
    function DecryptTrialTarget(decryptor, outQueue, maxSize) {
        this._decryptor = decryptor;
        this._outQueue = outQueue;
        this._maxSize = maxSize;
    }
    ns.DecryptTrialTarget = DecryptTrialTarget;


    // See TrialTarget#tryMe.
    // Our parameter is the `wireMessage`.
    DecryptTrialTarget.prototype.tryMe = function(pending, wireMessage) {
        var decrypted = this._decryptor(wireMessage);
        if (decrypted) {
            this._outQueue.push(decrypted);
            return true;
        }
        logger.debug('Message from "' + author
                     + ' not decrypted, will be stashed in trial buffer.');
        return false;
    };


    // See TrialTarget#maxSize.
    DecryptTrialTarget.prototype.maxSize = function() {
        return this._maxSize;
    };


    // See TrialTarget#paramId.
    // Our parameter is the `wireMessage`.
    DecryptTrialTarget.prototype.paramId = function(wireMessage) {
        var categorised = codec.categoriseMessage(wireMessage.message);
        return utils.sha256(categorised.content);
    };


    return ns;
});
