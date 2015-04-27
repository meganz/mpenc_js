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

    /** Default size in bytes for the exponential padding to pad to. */
    ns.DEFAULT_EXPONENTIAL_PADDING = 128;

    ns.PLAINTEXT_AUTO_RESPONSE = "We're not dealing with plaintext messages. Let's negotiate mpENC communication.";

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

        var self = this;

        // Set up a trial buffer for trial decryption.
        var decryptTarget = new ns.DecryptTrialTarget(
            function(message, authorHint) {
                return self._messageSecurity.decrypt(message, authorHint);
            }, this.uiQueue, 100);
        this._tryDecrypt = new struct.TrialBuffer(this.name, decryptTarget, false);

        // Set up component to manage membership operations
        this.greet = new greeter.GreetWrapper(this.id,
                                              privKey, pubKey,
                                              staticPubKeyDir,
                                              function(greet) { self.stateUpdatedCallback(self); });
        var cancelGreet = this.greet.subscribeSend(function(send_out) {
            var to = send_out[0], payload = send_out[1];
            self._pushMessage(to, payload);
        });

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

    ns.ProtocolHandler.prototype._pushMessage = function(to, encodedMessage) {
        this.protocolOutQueue.push({
            from: this.id,
            to: to,
            message: codec.tlvToWire(encodedMessage)
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
        this.greet.start(otherMembers);
    };


    /**
     * Start a new upflow for including new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to include into the group.
     */
    ns.ProtocolHandler.prototype.include = function(newMembers) {
        logger.debug('Invoking INCLUDE flow operation.');
        this.greet.include(newMembers);
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
        this.greet.exclude(excludeMembers);
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
        this.greet.quit();
    };


    /**
     * Refresh group key.
     *
     * @method
     */
    ns.ProtocolHandler.prototype.refresh = function() {
        logger.debug('Invoking REFRESH flow operation.');
        this.greet.refresh();
        this._messageSecurity = this._newMessageSecurity(this.greet);
    };


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
        this.greet.start(otherMembers);
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
        var classify = codec.getMessageAndType(wireMessage.message);
        if (!classify) {
            return;
        }

        switch (classify.type) {
            case codec.MESSAGE_TYPE.MPENC_ERROR:
                var errorMessageResult = codec.decodeErrorMessage(classify.content, this.greet.getEphemeralPubKey.bind(this.greet));
                this.uiQueue.push({
                    type: 'error',
                    message: codec.errorToUiString(errorMessageResult)
                });
                this.queueUpdatedCallback(this);
                if (errorMessageResult.severity === codec.ERROR.TERMINAL) {
                    this.quit();
                }
                break;
            case codec.MESSAGE_TYPE.PLAIN:
                var outMessage =
                wireMessage.type = 'info';
                wireMessage.message = 'Received unencrypted message, requesting encryption.';
                this.uiQueue.push(wireMessage);
                this.protocolOutQueue.push({
                    from: this.id,
                    to: wireMessage.from,
                    message: ns.PLAINTEXT_AUTO_RESPONSE
                });
                this._pushMessage(wireMessage.from, codec.MPENC_QUERY_MESSAGE);
                break;
            case codec.MESSAGE_TYPE.MPENC_QUERY:
                // Initiate keying protocol flow.
                this.start(wireMessage.from);
                break;
            case codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE:
                try {
                    var oldState = this.greet.state;
                    this.greet.processIncoming(wireMessage.from, classify.content);
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
                        this.sendError(codec.ERROR.TERMINAL, e.message);
                        return;
                    } else {
                        throw e;
                    }
                }
                break;
            case codec.MESSAGE_TYPE.MPENC_DATA_MESSAGE:
                var decodedMessage = null;
                _assert(this.greet.state === greeter.STATE.READY,
                        'Data messages can only be decrypted from a ready state.');

                this._tryDecrypt.trial(wireMessage);
                break;
            default:
                _assert(false, 'Received unknown message type: ' + classify.type);
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
        _assert(this.greet.state === greeter.STATE.READY,
                'Messages can only be sent in ready state.');
        var outMessage = {
            from: this.id,
            to: '',
            metadata: metadata,
            message: codec.tlvToWire(this._messageSecurity.encrypt(messageContent, this.exponentialPadding)),
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
        this._pushMessage('', codec.encodeErrorMessage({
            from: this.id,
            severity: severity,
            message: messageContent
        }, this.greet.getEphemeralPrivKey(), this.greet.getEphemeralPubKey()));

        if (severity === codec.ERROR.TERMINAL) {
            this.quit();
        }
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
        var decrypted = this._decryptor(codec.wireToTLV(wireMessage.message), wireMessage.from);
        if (decrypted) {
            this._outQueue.push(decrypted);
            return true;
        }
        logger.debug('Message from "' + wireMessage.from
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
        return utils.sha256(wireMessage.message);
    };


    return ns;
});
