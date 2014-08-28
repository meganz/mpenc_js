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
     * Carries message content for the mpENC protocol flow and data messages.
     *
     * @constructor
     * @param source {string}
     *     Message originator (from).
     * @returns {mpenc.messages.ProtocolMessage}
     *
     * @property source {string}
     *     Message originator (from).
     * @property dest {string}
     *     Message destination (to).
     * @property agreement {string}
     *     Type of key agreement. "initial" or "auxiliary".
     * @property flow {string}
     *     Direction of message flow. "upflow" or "downflow".
     * @property members {Array}
     *     List (array) of all participating members.
     * @property intKeys {Array}
     *     List (array) of intermediate keys for group key agreement.
     * @property debugKeys {Array}
     *     List (array) of keying debugging strings.
     * @property nonces {Array}
     *     Nonces of members for ASKE.
     * @property pubKeys {Array}
     *     Ephemeral public signing key of members.
     * @property sessionSignature {string}
     *     Session acknowledgement signature using sender's static key.
     * @property signingKey {string}
     *     Ephemeral private signing key for session (upon quitting participation).
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
    ns.ProtocolMessage = function(source) {
        this.source = source || '';
        this.dest = '';
        this.agreement = null;
        this.flow = null;
        this.members = [];
        this.intKeys = [];
        this.debugKeys = [];
        this.nonces = [];
        this.pubKeys = [];
        this.sessionSignature = null;
        this.signingKey = null;
        this.signature = null;
        this.signatureOk = false;
        this.rawMessage = null;
        this.protocol = null;
        this.data = null;

        return this;
    };

    /**
     * Carries information extracted from a received mpENC protocol message for
     * the greet protocol (key exchange and agreement).
     *
     * @constructor
     * @returns {mpenc.messages.ProtocolMessageInfo}
     *
     * @property type {string}
     *     String "mpEnc greet message".
     * @property protocol {integer}
     *     mpEnc protocol version number.
     * @property from {string}
     *     Message originator's participant ID.
     * @property to {string}
     *     Message destination's participant ID.
     * @property origin {string}
     *     Indicates whether the message originated from a group chat
     *     participant ("participant"), from somebody not participating
     *     ("outsider") or whether it cannot be determined/inferred by the
     *     recipient ("???").
     * @property greet {object}
     *     Introspective information for data carried by the greet protocol:
     *
     *     * `agreement` - "initial" or "auxiliary" key agreement.
     *     * `flow` - "upflow" (directed message) or "downflow" (broadcast).
     *     * `fromInitiator` {bool} - `true` if the flow initiator has sent the
     *       message, `false` if not, `null` if it can't be determined.
     *     * `negotiation` - A clear text expression of the type of negotiation
     *       message sent. One of "I quit", "somebody quits", "refresh",
     *       "exclude <subject>", "start <subject>" or "join <subject>" (with
     *       <subject> being one of "me", "other" or "(not involved)").
     *     * `members` - List of group members enclosed.
     *     * `numNonces` - Number of nonces enclosed.
     *     * `numPubKeys` - Number of public signing keys enclosed.
     *     * `numIntKeys` - Number of intermediate GDH keys enclosed.
     */
    ns.ProtocolMessageInfo = function() {
        this.type = null;
        this.protocol = null;
        this.from = null;
        this.to = null;
        this.origin = null;
        this.greet = {agreement: null,
                      flow: null,
                      fromInitiator: null,
                      negotiation: null,
                      members: [],
                      numNonces: 0,
                      numPubKeys: 0,
                      numIntKeys: 0,
        };

        return this;
    };


    return ns;
});
