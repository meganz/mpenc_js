/**
 * @fileOverview
 * Container object definition for message types.
 */

define([
    "mpenc/helper/assert",
], function(assert) {
    "use strict";

    /**
     * @exports mpenc/messages
     * Container object definition for message types.
     *
     * @description
     * <p>Container object definition for message types.</p>
     */
    var ns = {};

    /*
     * Created: 1 Apr 2014 Guy K. Kloss <gk@mega.co.nz>
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
    ns.ProtocolMessage = function(source, dest, agreement, flow, members,
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
     * Carries a data message's content.
     *
     * @constructor
     * @param signature {string}
     *     Binary signature string for the message
     * @param signatureOk {bool}
     *     Indicator whether the message validates. after message decoding.
     *     (Has to be done at time of message decoding as the symmetric block
     *     cipher employs padding.)
     * @param rawMessage {string}
     *     The raw message, after splitting off the signature. Can be used to
     *     re-verify the signature, if needed.
     * @param protocol {string}
     *     Single byte string indicating the protocol version using the binary
     *     version of the character.
     * @param data {string}
     *     Binary string containing the decrypted pay load of the message.
     * @returns {ProtocolMessage}
     *
     * @property signature {string}
     *     Binary signature string for the message
     * @property signatureOk {bool}
     *     Indicator whether the message validates. after message decoding.
     *     (Has to be done at time of message decoding as the symmetric block
     *     cipher employs padding.)
     * @property rawMessage {string}
     *     The raw message, after splitting off the signature. Can be used to
     *     re-verify the signature, if needed.
     * @property protocol {string}
     *     Single byte string indicating the protocol version using the binary
     *     version of the character.
     * @property data {string}
     *     Binary string containing the decrypted pay load of the message.
     */
    ns.DataMessage = function(signature, signatureOk, rawMessage, protocol, data) {
        this.signature = signature || '';
        this.signatureOk = signatureOk || false;
        this.rawMessage = rawMessage || '';
        this.protocol = protocol || '';
        this.data = data | '';
        
        return this;
    };



    return ns;
});
