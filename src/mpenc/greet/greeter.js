/*
 * Created: 2 Mar 2015 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/helper/async",
    "mpenc/helper/utils",
    "mpenc/greet/cliques",
    "mpenc/greet/ske",
    "mpenc/codec",
    "megalogger",
], function(assert, async, utils, cliques, ske, codec, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/greet/greet
     * @description
     * <p>Implementation of a greet (key agreement) protocol wrapper.</p>
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
    var _T = codec.TLV_TYPE;

    var logger = MegaLogger.getLogger('greeter', undefined, 'greet');


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
        READY:         0x03,
        AUX_UPFLOW:    0x04,
        AUX_DOWNFLOW:  0x05,
        QUIT:          0x06,
    };

    /** Mapping of state to string representation. */
    ns.STATE_MAPPING = {};
    for (var propName in ns.STATE) {
        ns.STATE_MAPPING[ns.STATE[propName]] = propName;
    }


    /**
     * Decodes a given TLV encoded Greet message into an object.
     *
     * @param message {string}
     *     A binary message representation.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param sessionID {string}
     *     Session ID.
     * @param groupKey {string}
     *     Symmetric group encryption key to encrypt message.
     * @returns {mpenc.codec.ProtocolMessage}
     *     Message as JavaScript object.
     */
    ns.decodeGreetMessage = function(message, pubKey, sessionID, groupKey) {
        var out = _decode(message);

        // Some specifics depending on the type of mpENC message.
        var sidkeyHash = '';
        _assert(!out.data);
        // Some sanity checks for keying messages.
        _assert(out.intKeys.length <= out.members.length,
                'Number of intermediate keys cannot exceed number of members.');
        _assert(out.nonces.length <= out.members.length,
                'Number of nonces cannot exceed number of members.');
        _assert(out.pubKeys.length <= out.members.length,
                'Number of public keys cannot exceed number of members.');

        // Check signature, if present.
        // TODO SECURITY REVIEW: why "if present"?
        if (out.signature) {
            if (!pubKey) {
                var index = out.members.indexOf(out.source);
                pubKey = out.pubKeys[index];
            }
            try {
                out.signatureOk = codec.verifyMessageSignature(codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                                                            out.rawMessage,
                                                            out.signature,
                                                            pubKey,
                                                            sidkeyHash);
                _assert(out.signatureOk,
                        'Signature of message does not verify!');
            } catch (e) {
                out.signatureOk = false;
                _assert(out.signatureOk,
                        'Signature of message does not verify: ' + e + '!');
            }
        }
        return out;
    };


    var _decode = function(message) {
        if (!message) {
            return null;
        }

        var out = new codec.ProtocolMessage();
        var debugOutput = [];
        var rest = message;

        rest = codec.popTLVMaybe(rest, _T.MESSAGE_SIGNATURE, function(value) {
            out.signature = value;
            debugOutput.push('messageSignature: ' + btoa(value));
        });
        if (rest !== message) {
            // there was a signature
            out.rawMessage = rest;
        }

        rest = codec.popStandardFields(rest, function(type) {
            if (type === codec.GREET_TYPE.PARTICIPANT_DATA) {
                return false;
            } else {
                out.greetType = type;
                return true;
            }
        }, "not PARTICIPANT_DATA", debugOutput);
        out.protocol = codec.PROTOCOL_VERSION;

        rest = codec.popTLV(rest, _T.SOURCE, function(value) {
            out.source = value;
            debugOutput.push('from: ' + value);
        });

        rest = codec.popTLV(rest, _T.DEST, function(value) {
            out.dest = value;
            debugOutput.push('to: ' + value);
        });

        rest = codec.popTLVAll(rest, _T.MEMBER, function(value) {
            out.members.push(value);
            debugOutput.push('member: ' + value);
        });

        rest = codec.popTLVAll(rest, _T.INT_KEY, function(value) {
            out.intKeys.push(value);
            debugOutput.push('intKey: ' + btoa(value));
        });

        rest = codec.popTLVAll(rest, _T.NONCE, function(value) {
            out.nonces.push(value);
            debugOutput.push('nonce: ' + btoa(value));
        });

        rest = codec.popTLVAll(rest, _T.PUB_KEY, function(value) {
            out.pubKeys.push(value);
            debugOutput.push('pubKey: ' + btoa(value));
        });

        rest = codec.popTLVMaybe(rest, _T.SESSION_SIGNATURE, function(value) {
            out.sessionSignature = value;
            debugOutput.push('sessionSignature: ' + btoa(value));
        });

        rest = codec.popTLVMaybe(rest, _T.SIGNING_KEY, function(value) {
            out.signingKey = value;
            debugOutput.push('signingKey: ' + btoa(value));
        });

        // TODO(xl): maybe complain if too much junk afterwards
        // Debugging output.
        logger.debug('mpENC decoded message debug: ', debugOutput);
        return out;
    };


    /**
     * Encodes a given greet message ready to be put onto the wire, using
     * base64 encoding for the binary message pay load.
     *
     * @param message {mpenc.codec.ProtocolMessage}
     *     Message as JavaScript object.
     * @param privKey {string}
     *     Sender's (ephemeral) private signing key.
     * @param pubKey {string}
     *     Sender's (ephemeral) public signing key.
     * @param paddingSize {integer}
     *     Number of bytes to pad the cipher text to come out as (default: 0
     *     to turn off padding). If the clear text will result in a larger
     *     cipher text than paddingSize, power of two exponential padding sizes
     *     will be used.
     * @returns {string}
     *     A wire ready message representation.
     */
    ns.encodeGreetMessage = function(message, privKey, pubKey, paddingSize) {
        if (message === null || message === undefined) {
            return null;
        }
        paddingSize = paddingSize | 0;

        var out = codec.ENCODED_VERSION;
        // Process message attributes in this order:
        // greetType, source, dest, members, intKeys, nonces, pubKeys,
        // sessionSignature, signingKey
        out += codec.encodeTLV(codec.TLV_TYPE.GREET_TYPE, message.greetType);
        out += codec.encodeTLV(codec.TLV_TYPE.SOURCE, message.source);
        out += codec.encodeTLV(codec.TLV_TYPE.DEST, message.dest);
        if (message.members) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.MEMBER, message.members);
        }
        if (message.intKeys) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.INT_KEY, message.intKeys);
        }
        if (message.nonces) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.NONCE, message.nonces);
        }
        if (message.pubKeys) {
            out += codec._encodeTlvArray(codec.TLV_TYPE.PUB_KEY, message.pubKeys);
        }
        if (message.sessionSignature) {
            out += codec.encodeTLV(codec.TLV_TYPE.SESSION_SIGNATURE, message.sessionSignature);
        }
        if (message.signingKey) {
            out += codec.encodeTLV(codec.TLV_TYPE.SIGNING_KEY, message.signingKey);
        }
        // Sign `out` and prepend signature.
        var signature = codec.signMessage(codec.MESSAGE_CATEGORY.MPENC_GREET_MESSAGE,
                                       out, privKey, pubKey);
        out = codec.encodeTLV(codec.TLV_TYPE.MESSAGE_SIGNATURE, signature) + out;

        return codec.encodeWireMessage(out);
    };


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
     * @param staticPubKeyDir {PubKeyDir}
     *     Public key directory object.
     * @param queueUpdatedCallback {Function}
     *      A callback function, that will be called every time something was
     *      added to `protocolOutQueue`, `messageOutQueue` or `uiQueue`.
     * @param stateUpdatedCallback {Function}
     *      A callback function, that will be called every time the `state` is
     *      changed.
     * @returns {GreetWrapper}
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
     * @property askeMember {SignatureKeyExchangeMember}
     *      Reference to signature key exchange protocol handler with the same
     *      participant ID.
     * @property cliquesMember {CliquesMember}
     *     Reference to CLIQUES protocol handler with the same participant ID.
     * @property state {integer}
     *     Current state of the mpENC protocol handler according to {STATE}.
     * @property recovering {bool}
     *     `true` if in recovery mode state, usually `false`.
     */
    var GreetWrapper = function(id, privKey, pubKey, staticPubKeyDir, stateUpdatedCallback) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.state = ns.STATE.NULL;
        this.stateUpdatedCallback = stateUpdatedCallback || function() {};
        this.recovering = false;

        this._send = new async.Observable(true);

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
    ns.GreetWrapper = GreetWrapper;

    GreetWrapper.prototype._updateState = function(state) {
        this.state = state;
        this.stateUpdatedCallback(this);
    };

    GreetWrapper.prototype._assertState = function(valid, message) {
        _assert(valid.some(function(v) {
            return this.state === v;
        }, this), message);
    };

    GreetWrapper.prototype._encodeAndPublish = function(protocolMessage) {
        if (!protocolMessage) return;
        var payload = ns.encodeGreetMessage(
            protocolMessage,
            this.getEphemeralPrivKey(),
            this.getEphemeralPubKey());
        // TODO(xl): use a RawSendT instead of Array[2]
        this._send.publish([protocolMessage.dest, payload]);
    };

    GreetWrapper.prototype.subscribeSend = function(subscriber) {
        return this._send.subscribe(subscriber);
    };

    /**
     * Mechanism to start the protocol negotiation with the group participants.
     *
     * @method
     * @param otherMembers {Array}
     *     Iterable of other members for the group (excluding self).
     */
    GreetWrapper.prototype.start = function(otherMembers) {
        this._assertState([ns.STATE.NULL],
                'start() can only be called from an uninitialised state.');
        _assert(otherMembers && otherMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.ika(otherMembers);
        var askeMessage = this.askeMember.commit(otherMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.greetType = codec.GREET_TYPE.RECOVER_INIT_INITIATOR_UP;
        } else {
            protocolMessage.greetType = codec.GREET_TYPE.INIT_INITIATOR_UP;
        }

        if (protocolMessage.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
        } else {
            this._encodeAndPublish(protocolMessage);
            this._updateState(ns.STATE.INIT_UPFLOW);
        }
    };


    /**
     * Mechanism to start a new upflow for including new members.
     *
     * @method
     * @param newMembers {Array}
     *     Iterable of new members to include into the group.
     */
    GreetWrapper.prototype.include = function(newMembers) {
        this._assertState([ns.STATE.READY],
                'include() can only be called from a ready state.');
        _assert(newMembers && newMembers.length !== 0, 'No members to add.');

        var cliquesMessage = this.cliquesMember.akaJoin(newMembers);
        var askeMessage = this.askeMember.join(newMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        protocolMessage.greetType = codec.GREET_TYPE.INCLUDE_AUX_INITIATOR_UP;
        this._updateState(ns.STATE.AUX_UPFLOW);
        this._encodeAndPublish(protocolMessage);
    };


    /**
     * Mechanism to start a new downflow for excluding members.
     *
     * @method
     * @param excludeMembers {Array}
     *     Iterable of members to exclude from the group.
     */
    GreetWrapper.prototype.exclude = function(excludeMembers) {
        if (this.recovering) {
            this._assertState([ns.STATE.READY, ns.STATE.INIT_DOWNFLOW, ns.STATE.AUX_DOWNFLOW],
                    'exclude() for recovery can only be called from a ready or downflow state.');
        } else {
            this._assertState([ns.STATE.READY],
                    'exclude() can only be called from a ready state.');
        }
        _assert(excludeMembers && excludeMembers.length !== 0, 'No members to exclude.');
        _assert(excludeMembers.indexOf(this.id) < 0,
                'Cannot exclude mysefl.');

        var cliquesMessage = this.cliquesMember.akaExclude(excludeMembers);
        var askeMessage = this.askeMember.exclude(excludeMembers);

        var protocolMessage = this._mergeMessages(cliquesMessage, askeMessage);
        if (this.recovering) {
            protocolMessage.greetType = codec.GREET_TYPE.RECOVER_EXCLUDE_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.greetType = codec.GREET_TYPE.EXCLUDE_AUX_INITIATOR_DOWN;
        }

        // We need to update the session state.
        this.sessionId = this.askeMember.sessionId;
        this.members = this.askeMember.members;
        this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
        this.groupKey = this.cliquesMember.groupKey;

        if (protocolMessage.members.length === 1) {
            // Last-man-standing case,
            // as we won't be able to complete the protocol flow.
            this.quit();
        } else {
            if (this.isSessionAcknowledged()) {
                this._updateState(ns.STATE.READY);
            } else {
                this._updateState(ns.STATE.AUX_DOWNFLOW);
            }
            this._encodeAndPublish(protocolMessage);
        }
    };


    /**
     * Mechanism to start the downflow for quitting participation.
     *
     * @method
     */
    GreetWrapper.prototype.quit = function() {
        if (this.state === ns.STATE.QUIT) {
            return; // Nothing do do here.
        }

        _assert(this.getEphemeralPrivKey() !== null,
                'Not participating.');

        this.cliquesMember.akaQuit();
        var askeMessage = this.askeMember.quit();

        var protocolMessage = this._mergeMessages(null, askeMessage);
        protocolMessage.greetType = codec.GREET_TYPE.QUIT_DOWN;
        this._updateState(ns.STATE.QUIT);
        this._encodeAndPublish(protocolMessage);
    };


    /**
     * Mechanism to refresh group key.
     *
     * @method
     */
    GreetWrapper.prototype.refresh = function() {
        this._assertState([ns.STATE.READY, ns.STATE.INIT_DOWNFLOW, ns.STATE.AUX_DOWNFLOW],
                'refresh() can only be called from a ready or downflow states.');
        var cliquesMessage = this.cliquesMember.akaRefresh();

        var protocolMessage = this._mergeMessages(cliquesMessage, null);
        if (this.recovering) {
            protocolMessage.greetType = codec.GREET_TYPE.RECOVER_REFRESH_AUX_INITIATOR_DOWN;
        } else {
            protocolMessage.greetType = codec.GREET_TYPE.REFRESH_AUX_INITIATOR_DOWN;
        }
        // We need to update the group key.
        this.groupKey = this.cliquesMember.groupKey;
        this._updateState(ns.STATE.READY);
        this._encodeAndPublish(protocolMessage);
    };


    GreetWrapper.prototype.processIncoming = function(from, content) {
        var decodedMessage = null;
        if (this.getEphemeralPubKey()) {
            // In case of a key refresh (groupKey existent),
            // the signing pubKeys won't be part of the message.
            // TODO(gk): xl: but we're not checking if this is a key refresh here?
            var signingPubKey = this.getEphemeralPubKey(from);
            decodedMessage = ns.decodeGreetMessage(content, signingPubKey);
        } else {
            decodedMessage = ns.decodeGreetMessage(content);
        }
        var oldState = this.state;
        var keyingMessageResult = this._processMessage(decodedMessage);
        if (keyingMessageResult === null) {
            return;
        }
        this._encodeAndPublish(keyingMessageResult.decodedMessage);
        if (keyingMessageResult.newState &&
                (keyingMessageResult.newState !== oldState)) {
            // Update the state if required.
            logger.debug('Reached new state: '
                         + ns.STATE_MAPPING[keyingMessageResult.newState]);
            this._updateState(keyingMessageResult.newState);
        }
    };

    /**
     * Handles greet (key agreement) protocol execution with all participants.
     *
     * @method
     * @param message {ProtocolMessage}
     *     Received message (decoded). See {@link ProtocolMessage}.
     * @returns {object}
     *     Object containing the decoded message content as
     *     {ProtocolMessage} in attribute `decodedMessage` and
     *     optional (null if not used) the new the GreetWrapper state in
     *     attribute `newState`.
     */
    GreetWrapper.prototype._processMessage = function(message) {
        logger.debug('Processing message of type '
                     + message.getGreetTypeString());
        if (this.state === ns.STATE.QUIT) {
            // We're not par of this session, get out of here.
            logger.debug("Ignoring message as we're in state QUIT.");
            return null;
        }

        // If I'm not part of it any more, go and quit.
        if (message.members && (message.members.length > 0)
                && (message.members.indexOf(this.id) === -1)) {
            if (this.state !== ns.STATE.QUIT) {
                return { decodedMessage: null,
                         newState: ns.STATE.QUIT };
            } else {
                return null;
            }
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
        if (message.greetType === codec.GREET_TYPE.QUIT_DOWN) {
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
                outAskeMessage = this.askeMember.downflow(inAskeMessage);
            }
            outMessage = this._mergeMessages(null, outAskeMessage);
            if (outMessage) {
                outMessage.greetType = message.greetType;
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
            outMessage.greetType = message.greetType;
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
            // Let's update our state information.
            newState = ns.STATE.READY;
            this.sessionId = this.askeMember.sessionId;
            this.members = this.askeMember.members;
            this.ephemeralPubKeys = this.askeMember.ephemeralPubKeys;
            this.groupKey = this.cliquesMember.groupKey;
            logger.debug('Reached READY state.');
            this.recovering = false;
        }

        if (outMessage) {
            logger.debug('Sending message of type '
                         + outMessage.getGreetTypeString());
        } else {
            logger.debug('No message to send.');
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
     * @returns {ProtocolMessage}
     *     Joined message (not wire encoded).
     */
    GreetWrapper.prototype._mergeMessages = function(cliquesMessage,
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
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.cliques.CliquesMessage}
     *     Extracted message.
     */
    GreetWrapper.prototype._getCliquesMessage = function(message) {
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
     * @param message {ProtocolMessage}
     *     Message from protocol handler.
     * @returns {mpenc.greet.ske.SignatureKeyExchangeMessage}
     *     Extracted message.
     */
    GreetWrapper.prototype._getAskeMessage = function(message) {
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


    /**
     * Gets the ephemeral private key (the own one).
     *
     * @method
     * @returns {string}
     */
    GreetWrapper.prototype.getEphemeralPrivKey = function() {
        return this.askeMember.ephemeralPrivKey;
    };


    /**
     * Gets the ephemeral public key of a participant.
     *
     * @method
     * @param participantID {string}
     *     Participant ID to return. If left blank, one's own ephemeral public
     *     signing key is returned.
     * @returns {string}
     *     Ephemeral public signing key.
     */
    GreetWrapper.prototype.getEphemeralPubKey = function(participantID) {
        if (participantID === undefined || participantID === this.id) {
            return this.askeMember.ephemeralPubKey;
        } else {
            if (this.askeMember.ephemeralPubKeys
                    && this.askeMember.ephemeralPubKeys.length > 0) {
                return this.askeMember.getMemberEphemeralPubKey(participantID);
            } else {
                return undefined;
            }
        }
    };


    /**
     * Returns true if the authenticated signature key exchange is fully
     * acknowledged.
     *
     * @method
     * @returns {boolean}
     *     True on a valid session.
     */
    GreetWrapper.prototype.isSessionAcknowledged = function(participantID) {
        return this.askeMember.isSessionAcknowledged();
    };


    /**
     * Discard all authentications, and set only self to authenticated.
     *
     * @method
     */
    GreetWrapper.prototype.discardAuthentications = function() {
        this.askeMember.discardAuthentications();
    };


    /**
     * Returns the current session ID.
     *
     * @method
     * @returns {string}
     */
    GreetWrapper.prototype.getSessionId = function() {
        return this.askeMember.sessionId;
    };


    /**
     * Returns the current members.
     *
     * @method
     * @returns {array<string>}
     */
    GreetWrapper.prototype.getMembers = function() {
        return this.askeMember.members;
    };


    /**
     * Returns the current ephemeral public keys.
     *
     * @method
     * @returns {array<string>}
     */
    GreetWrapper.prototype.getEphemeralPubKeys = function() {
        return this.askeMember.ephemeralPubKeys;
    };


    /**
     * Returns the current group key.
     *
     * @method
     * @returns {string}
     */
    GreetWrapper.prototype.getGroupKey = function() {
        return this.cliquesMember.groupKey;
    };



    return ns;
});
