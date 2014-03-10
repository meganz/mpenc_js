/**
 * @fileOverview
 * Implementation of a protocol handler with its state machine.
 */

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
 * @property nonces
 *     Nonces of members for ASKE.
 * @property pubKeys
 *     Ephemeral public signing key of members.
 * @property sessionSignature
 *     Session acknowledgement signature using sender's static key.
 */
mpenc.handler.ProtocolMessage = function(source, dest, agreement, flow, members,
                                         intKeys, nonces, pubKeys, sessionSignature) {
    this.source = source || '';
    this.dest = dest || '';
    this.agreement = agreement || '';
    this.flow = flow || '';
    this.members = members || [];
    this.intKeys = intKeys || [];
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
 * @param otherMembers
 *     Iterable of other members for the group (excluding self).
 * @returns {ProtocolMessage}
 * @method
 */
mpenc.handler.ProtocolHandler.prototype.start = function(otherMembers) {
    _assert(otherMembers.length !== 0, 'No members to add.');
    
    var cliquesMessage = this.cliquesMember.ika(otherMembers);
    var askeMessage = this.askeMember.commit(otherMembers);
    
    return this._mergeMessages(cliquesMessage, askeMessage);
};


/**
 * Handles protocol execution with all participants.
 * 
 * @param message
 *     Received message. See {@link ProtocolMessage}.
 * @returns {ProtocolMessage}
 * @method
 */
mpenc.handler.ProtocolHandler.prototype.processMessage = function(message) {
    var inCliquesMessage = this._getCliquesMessage(message);
    var inAskeMessage = this._getAskeMessage(message);
    
    var outCliquesMessage = this.cliquesMember.upflow(inCliquesMessage);
    var outAaskeMessage = this.askeMember.upflow(inAskeMessage);
    
    return this._mergeMessages(outCliquesMessage, outAaskeMessage);
};


/**
 * Merges the contents of the messages for ASKE and CLIQUES into one message..
 * 
 * @param cliquesMessage
 *     Message from CLIQUES protocol workflow.
 * @param askeMessage
 *     Message from ASKE protocol workflow.
 * @returns {ProtocolMessage}
 *     Joined message.
 * @method
 */
mpenc.handler.ProtocolHandler.prototype._mergeMessages = function(cliquesMessage,
                                                                  askeMessage) {
    var newMessage = mpenc.handler.ProtocolMessage(this.id);
    _assert(cliquesMessage.source === askeMessage.source,
            "Message source mismatch, this shouldn't happen.");
    _assert(cliquesMessage.dest === askeMessage.dest,
            "Message destination mismatch, this shouldn't happen.");
    newMessage.dest = cliquesMessage.dest;
    newMessage.flow = cliquesMessage.flow;
    newMessage.members = cliquesMessage.members;
    newMessage.intKeys = cliquesMessage.intKeys;
    newMessage.nonces = askeMessage.nonces;
    newMessage.pubKeys = askeMessage.pubKeys;
    newMessage.sessionSignature = askeMessage.sessionSignature;
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
 * @param message {ProtocolMessage}
 *     Message from protocol handler.
 * @returns {mpenc.cliques.CliquesMessage}
 *     Extracted message.
 * @method
 */
mpenc.handler.ProtocolHandler.prototype._getCliquesMessage = function(message) {
    var newMessage = mpenc.cliques.CliquesMessage(this.id);
    newMessage.source = message.source;
    newMessage.dest = message.dest;
    newMessage.flow = message.flow;
    newMessage.members = message.members;
    newMessage.intKeys = message.intKeys;
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
 * @param message {ProtocolMessage}
 *     Message from protocol handler.
 * @returns {mpenc.ske.SignatureKeyExchangeMessage}
 *     Extracted message.
 * @method
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
