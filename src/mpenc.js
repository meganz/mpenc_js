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
    "mpenc/impl/transcript",
    "mpenc/greet/greeter",
    "mpenc/helper/async",
    "mpenc/helper/struct",
    "megalogger"
], function(
    version, session, message, channel,
    applied, sessionImpl, transcriptImpl, greeter,
    async, struct, MegaLogger
) {
    "use strict";

    /**
     * @exports mpenc
     * @description
     *
     * The multi-party encrypted chat protocol, public API.
     *
     * @example
     *
     * // variables beginning '?' you need to supply yourself; see the
     * // the relevant function doc for details, further below.
     *
     * // Initialisation
     *
     * var mpenc = // however you import it, AMD, Common-JS, whatever
     * var timer = mpenc.createTimer();
     * var context = mpenc.createContext(
     *     ?userId, timer, ?privKey, ?pubKey, ?pubKeyDir);
     *
     * // Prepare to have a group chat:
     *
     * var groupChannel = // you need to implement your own, see docs.
     *                    // this is the most signficant part to prepare.
     * var session = mpenc.createSession(
     *     context, ?sessionId, groupChannel, ?options);
     *
     * // TODO: how to send actions, receive notices, make queries
     */
    var mpenc = {};

    // Create the name space's root logger.
    MegaLogger.getLogger('mpenc');

    // Create two more loggers for name spaces without their own modules.
    MegaLogger.getLogger('helper', undefined, 'mpenc');
    MegaLogger.getLogger('greet', undefined, 'mpenc');

    mpenc.version = version;


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
     * @param privKey {string}
     *      The long-term Ed25519 private key for the local user, as a sequence
     *      of 8-bit characters representing bytes.
     * @param pubKey {string}
     *      The long-term Ed25519 public key for the local user, as a sequence
     *      of 8-bit characters representing bytes.
     * @param pubKeyDir {{get: function}}
     *      Object with a 1-arg "get" method for obtaining long-term Ed25519
     *      public keys for other members (user Ids).
     * @returns {SessionContext}
     * @memberOf module:mpenc
     */
    var createContext = function(userId, timer, privKey, pubKey, pubKeyDir, flowControl) {
        return new sessionImpl.SessionContext(
            userId, false, timer, privKey, pubKey, pubKeyDir,
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


    // expose some internals to help external implementations

    mpenc.helper = {
        async: async,
        struct: struct
    };

    mpenc.channel = channel;
    mpenc.session = session;
    mpenc.applied = applied;

    return mpenc;
});
