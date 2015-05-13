/*
 * Created: 08 May 2015 Michael Holmwood <mh@mega.co.nz>
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
    "mpenc/greet/greeter",
    "mpenc/helper/utils",
], function(assert, greeter, utils) {
    "use strict";

    /**
     * @exports mpenc/greet/greetstore
     * @description
     * <p>This file contains two classes, GreetStore and GreetStoreFactory.</p>
     *
     * <p>Greetstore is used to encapsulate all of the state data required to reproduce
     * a Greeter from the point it was destroyed.</p>
     *
     * <p>GreetStoreFactory is a factory class that keeps track of the static data for all
     * greeters, and provides functions to create a GreetStore from a Greeter, and vice versa.</p>
     *
     */
    var ns = {};

    var _assert = assert.assert;

    /**
     * @description SessionStore holds all of the public and private data required to
     * restore a greet object to a given state.
     *
     * @constructor
     * @param greet {Greeter}
     *      The Greeter object to obtain the state data to store.
     * @property _send {Array}
     *      The array of recipients to broadcast send notifications to.
     * @property sessionId {string}
     *      The id for the session.
     * @property ephemeralPubKeys {array<string>}
     *      The ephemeral signing keys for the other members in the chat session.
     * @property ephemeralPubKey {string}
     *      The ephemeral public key for <b>this</b> member.
     * @property ephemeralPrivKey {string}
     *      The ephemeral private key for <b>this</b> member.
     * @property nonces {array<string>}
     *      The nonces for the other members in the chat session.
     * @property nonce {string}
     *      The nonce for <b>this</b> member.
     * @property askeMembers {array<string>}
     *      The members for the greet session.
     * @property groupKey {string}
     *      The group secret key for this session.
     * @property privKeyList {array<string>}
     *      The list of private contributions for <b>this</b> member.
     * @property intKeys {array<string>}
     *      The list of previous initial keys for all members.
     */
    var GreetStore = function(greet) {
        // Greeter Objects.
        this._send = utils.clone(greet._send);

        // Aske Objects.
        this.sessionId = greet.askeMember.sessionId;
        this.ephemeralPubKeys = utils.clone(greet.askeMember.ephemeralPubKeys);
        this.ephemeralPubKey = utils.clone(greet.askeMember.ephemeralPubKey);
        this.ephemeralPrivKey = utils.clone(greet.askeMember.ephemeralPrivKey);
        this.nonces = utils.clone(greet.askeMember.nonces);
        this.nonce = utils.clone(greet.askeMember.nonce);
        this.askemembers = utils.clone(greet.askeMember.members);

        // Cliques Objects.
        this.groupKey = utils.clone(greet.cliquesMember.groupKey);
        this.privKeyList = utils.clone(greet.cliquesMember.privKeyList);
        this.intKeys = utils.clone(greet.cliquesMember.intKeys);

        return this;
    };

    ns.GreetStore = GreetStore;

    /**
     * @method
     *
     * @description Convert a GreetStore object to a Greeter object.
     *
     * @param id {string}
     *      Members identification string.
     * @param priKey {string}
     *      The members static private key.
     * @param pubKey {string}
     *      The members static public key.
     * @param staticPubKeyDir {function}
     *      Callback to obtain public signing keys for other members.
     * @param stateUpdatedCallback {function}
     *      Callback to notify of state changes.
     * @returns {*|GreetWrapper}
     */
    ns.GreetStore.prototype.toGreeter = function(id, priKey, pubKey, staticPubKeyDir, stateUpdatedCallback) {

        var gr = new greeter.GreetWrapper(id, priKey, pubKey, staticPubKeyDir, stateUpdatedCallback);

        // Greeter Objects.
        //gr.members = utils.clone(this.members);
        gr.state = greeter.STATE.READY;
        gr._send = utils.clone(this._send);

        // Aske Objects.
        gr.askeMember.sessionId = this.sessionId;
        gr.askeMember.ephemeralPubKeys = utils.clone(this.ephemeralPubKeys);
        gr.askeMember.ephemeralPubKey = utils.clone(this.ephemeralPubKey);
        gr.askeMember.ephemeralPrivKey = utils.clone(this.ephemeralPrivKey);
        gr.askeMember.nonce = utils.clone(this.nonce);
        gr.askeMember.nonces = utils.clone(this.nonces);
        gr.askeMember.members = utils.clone(this.askemembers);
        gr.askeMember.authenticatedMembers = [];

        // Cliques Objects.
        gr.cliquesMember.groupKey = utils.clone(this.groupKey);
        gr.cliquesMember.privKeyList = utils.clone(this.privKeyList);
        gr.cliquesMember.intKeys = utils.clone(this.intKeys);
        gr.cliquesMember.members = utils.clone(this.askemembers);

        return gr;
    };

    /**
     * @constructor
     *
     * @description Constructor for GreetStoreFactory.
     *
     * @param id {string}
     *      The id for <b>this</b> member.
     * @param privKey
     *      The static private key for <b>this</b> member.
     * @param pubKey
     *      The static public key for <b>this</b> member.
     * @param staticPubKeyDir
     *      Callback to obtain public keys for <b>other</b> memebrs.
     * @param stateUpdatedCallBack
     *      Callback to notify of updates to protocol state.
     * @returns {GreetStoreFactory}
     */
    var GreetStoreFactory = function(id, privKey, pubKey, staticPubKeyDir, stateUpdatedCallBack) {
        this.id = id;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.staticPubKeyDir = staticPubKeyDir;
        this.stateUpdatedCallback = stateUpdatedCallBack;

        _assert(this.id && this.privKey && this.pubKey && this.staticPubKeyDir,
                'Constructor call missing required parameters');

        return this;
    };

    ns.GreetStoreFactory = GreetStoreFactory;

    /**
     * @method
     *
     * @description Method to create a GreetStore object from a Greeter object.
     *
     * </p>All of the relevant data is copied from the Greeter object into the GreetStore object.</p>
     * @param greet {mpenc.greet.Greeter}
     *      The Greeter to create the GreetStore from.
     * @returns {GreetStore}
     */
    ns.GreetStoreFactory.prototype.greeterToStore = function(greet) {
        // Ensure that the current state is ready.
        console.log("Creating store for id: ", this.id);
        _assert(greet.state === greeter.STATE.READY); //*
        return new GreetStore(greet);
    };

    /**
     * @method
     *
     * @description Method to create a Greeter from a GreetStore object.
     *
     * <p>The created Greeter will have the exact same state and data as the one it was created from.</p>
     *
     * @param store {GreetStore}
     *      The store to recreate the Greeter object from.
     * @returns {*|GreetWrapper}
     */
    ns.GreetStoreFactory.prototype.storeToGreeter = function(store) {
        console.log("Creating greeter for id: ", this.id);
        return store.toGreeter(this.id, this.privKey, this.pubKey, this.staticPubKeyDir,
                                    this.stateUpdatedCallback);
    };

    return ns;
});