/*
 * Created: 11 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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
    "mpenc/version",
    "mpenc/session",
    "mpenc/message",
    "mpenc/channel",
    "mpenc/impl/applied",
    "mpenc/impl/session",
    "mpenc/impl/channel",
    "mpenc/impl/transcript",
    "mpenc/greet/greeter",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "mpenc/helper/utils",
    "megalogger"
], function(
    version, session, message, channel,
    applied, sessionImpl, channelImpl, transcriptImpl, greeter,
    async, struct, utils, MegaLogger
) {
    "use strict";

    /**
     * @exports mpenc
     * @description
     *
     * The multi-party encrypted chat protocol, public API entry point.
     *
     * @example
     *
     * // Variables beginning '?' you need to supply yourself; see the
     * // the relevant function doc for details, further below.
     *
     * // Initialisation
     *
     * var mpenc = // however you import it, AMD, Common-JS, whatever
     * var timer = mpenc.createTimer();
     * var ownKeyPair = mpenc.createKeyPair(); // or, load it from somewhere else
     * var context = mpenc.createContext(
     *   ?userId, timer, ownKeyPair, ?pubKeyDir);
     *
     * // Prepare to have a group chat:
     *
     * var groupChannel = // you must implement your own, e.g. by extending
     *   // mpenc/impl/channel.BaseGroupChannel; see docs for more details.
     * var session = mpenc.createSession(
     *   context, ?sessionId, groupChannel, ?options);
     *
     * // For interacting with the session, see mpenc/session.Session
     */
    var mpenc = {
        // public API, matching the documentation
        channel: channel,
        helper: {
            async: async,
            struct: struct,
        },
        impl: {
            applied: applied,
            channel: {
                BaseGroupChannel: channelImpl.BaseGroupChannel,
            },
        },
        session: session,
        version: version,
    };

    // Create the name space's root logger.
    MegaLogger.getLogger('mpenc');

    // Create two more loggers for name spaces without their own modules.
    MegaLogger.getLogger('helper', undefined, 'mpenc');
    MegaLogger.getLogger('greet', undefined, 'mpenc');


    /**
     * @typedef SignatureKeyPair
     * @type Object
     * @property privKey {string} Ed25519 private key, as a string of 8-bit
     *      characters, to be kept secret and local to this device. For
     *      historical reasons we use the "key seed", i.e. `k` as per
     *      python-ed25519, rather than `a || RH` as per NaCl. See [Ed25519
     *      Keys](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/) for
     *      more details.
     * @property pubKey {string} Ed25519 public key, as a string of 8-bit
     *      characters, to be distributed to your contacts so that they may
     *      distinguish you from an active attacker. (This has the same value
     *      across multiple implementations.)
     */


    /**
     * Default flow control.
     *
     * Contains various parameters that control timing for auto-acks, trial
     * decryption buffer sizes, consistency warning events, etc.
     *
     * TODO(xl): FlowControl will be defined "properly" as per python in a
     * later release.
     */
    var DEFAULT_FLOW_CONTROL = {
        // Estimated 95-percentile values; TODO: research/tweak these later
        getBroadcastLatency: function() {
            // 5 seconds to broadcast (half-round-trip) to *everyone*
            return 5000;
        },
        getFullAckInterval: function() {
            // 16 seconds to reply to a message
            return 16000 + 2 * this.getBroadcastLatency();
        },
        asynchronity: function() {
            // 4 messages "in transit" on the wire
            return 4;
        },
    };


    /** Default size in bytes for the exponential padding to pad to. */
    var DEFAULT_EXPONENTIAL_PADDING = 128;


    /**
     * Create a new timer to run scheduled tasks.
     *
     * There should only be one of these in the entire application.
     *
     * @returns {module:mpenc/helper/async.Timer}
     * @memberOf module:mpenc
     */
    var createTimer = function() {
        return new async.Timer();
    };
    mpenc.createTimer = createTimer;


    /**
     * Create a key pair for the user.
     *
     * There should only be one of these per user (or device), shared between
     * all their sessions. It is highly recommended that you persist this in
     * long-term storage, otherwise your contacts will not be able to (x)
     * distinguish you from a man-in-the-middle attacker.
     *
     * Some applications try to offer protection against forensic analysis by
     * making these keys ephemeral (i.e. generating new ones for every session)
     * and delegating the security concern at (x) to some other material such
     * as a shared secret to be memorised for each contact. However, getting
     * this right is very tricky, more often than not *decreases* security, and
     * there has not yet been a "preferred standard approach" for it. We do not
     * provide such an approach in this library, and we recommended you not to
     * implement such an approach yourself, unless you understand exactly why
     * it is safe to ignore our recommendation for your case. When unsure, just
     * persist the key in the user's `localStorage`, or another store if that
     * is better, such as a system keyring.
     *
     * @param [privKey] {string} An existing private key loaded from persistent
     *      secure storage, as a string of 8-bit characters. If omitted, we
     *      generate a new one using the asmCrypto RNG, which delegates in part
     *      to the system RNG.
     * @returns {module:mpenc~SignatureKeyPair} Your own key pair that includes
     *      both the private and public parts of the key.
     * @memberOf module:mpenc
     */
    var createKeyPair = function(privKey) {
        privKey = privKey || utils.randomString(32);
        return {
            privKey: privKey,
            pubKey: utils.toPublicKey(privKey),
        };
    };
    mpenc.createKeyPair = createKeyPair;


    /**
     * Create a new context for sessions.
     *
     * There should only be one of these per user (or device), shared between
     * all their sessions.
     *
     * The returned context is an opaque object and we give no public API for
     * it. Clients of this library should not need to interact with the object;
     * you merely keep it around to pass to {@link module:mpenc.createSession}.
     *
     * @param userId {string}
     *      Global identifier for the local user.
     * @param timer {module:mpenc/helper/async.Timer}
     *      Timer; e.g. see {@link module:mpenc.createTimer}. You do not *have*
     *      to use that function; you can pass in anything here that satisfies
     *      our expected interface - such as a third-party execution framework
     *      or event loop, or if necessary an adapter to them that matches our
     *      expected interface. Be aware of behavioural restrictions such as
     *      ordering, not just the function parameter types.
     * @param ownKeyPair {module:mpenc~SignatureKeyPair}
     *      The Ed25519 long-term (identity) key pair for the local user; e.g.
     *      see {@link module:mpenc.createKeyPair}.
     * @param pubKeyDir {{get: function}}
     *      Object with a 1-arg "get" method (userId -> pubKey) for obtaining
     *      Ed25519 long-term (identity) public keys for other members.
     * @returns {SessionContext}
     * @memberOf module:mpenc
     */
    var createContext = function(userId, timer, ownKeyPair, pubKeyDir, flowControl) {
        return new sessionImpl.SessionContext(
            userId, false, timer, ownKeyPair.privKey, ownKeyPair.pubKey, pubKeyDir,
            flowControl || DEFAULT_FLOW_CONTROL,
            message.DefaultMessageCodec,
            transcriptImpl.DefaultMessageLog);
    };
    mpenc.createContext = createContext;


    /**
     * Create a new group session.
     *
     * @param context {SessionContext}
     *      Session context; see {@link module:mpenc.createContext}.
     * @param sessionId {string}
     *      A unique identifier for this session, constant across all members.
     * @param groupChannel {module:mpenc/channel.GroupChannel}
     *      Group transport client / adapter object, for the session to be able
     *      to communicate with the outside world. For example, one can wrap an
     *      XMPP client library to implement this object. See the documentation
     *      for the class type, for details how we expect it to behave.
     * @param [options] {Object} Tweak some behaviours; see below. Note that
     *      non-default values are, in some sense, "less safe" than the default
     *      values; please be aware of this and don't surprise your users.
     * @param [options.autoIncludeExtra] {boolean} Whether to automatically include
     *      new members that enter the transport channel. Default: false.
     * @param [options.stayIfLastMember] {boolean} Whether to remain in the channel
     *      instead of leaving it, as the last member. Default: false.
     * @returns {module:mpenc/session.Session}
     * @memberOf module:mpenc
     */
    var createSession = function(context, sessionId, groupChannel, options) {
        return new sessionImpl.HybridSession(
            context, sessionId, groupChannel,
            new greeter.Greeter(context.owner, context.privKey, context.pubKey, context.pubKeyDir),
            function(greetState) {
                return new message.MessageSecurity(greetState, DEFAULT_EXPONENTIAL_PADDING);
            }, options);
    };
    mpenc.createSession = createSession;


    return mpenc;
});
