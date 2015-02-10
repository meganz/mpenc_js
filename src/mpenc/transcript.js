/**
 * @fileOverview
 * Transcript interfaces.
 */

define([], function() {
    "use strict";

    /**
     * @exports mpenc/transcript
     * Transcript interfaces.
     *
     * @description
     * Transcript interfaces.
     */
    var ns = {};

    /*
     * Created: 28 Mar 2014 Ximin Luo <xl@mega.co.nz>
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
     * A set of Messages forming all or part of a session.
     *
     * @interface
     * @memberOf module:mpenc/transcript
     */
    var Messages = function() {
        throw new Error("cannot instantiate an interface");
    };

    /**
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/message.Message} Message object for the id. */
    Messages.prototype.get;

    /**
     * The immediately-preceding messages seen by the author of mId.
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of mIds. */
    Messages.prototype.parents;

    /**
     * The recipients that have not acked the given message, as seen by
     * the local process. If this is empty, the message has been fully-acked.
     *
     * We (the local process) consider a message m authored by u to be "acked"
     * by a recipient ru, iff we have accepted a message m_a authored by ru
     * where m <= m_a, and there is a chain of messages [m .. m_a] all of
     * which are visible to ru (i.e. authored by them, or by another to them).
     *
     * @method
     * @param {string} mId
     * @returns {module:mpenc/helper/struct.ImmutableSet} Set of uIds. */
    Messages.prototype.unackby;

    /**
     * Messages that are not yet fully-acked.
     * @method
     * @returns {Array.<string>} List of mIds in some topological order. */
    Messages.prototype.unacked;

    Object.freeze(Messages.prototype);
    ns.Messages = Messages;


    /**
     * A Transcript.
     *
     * TODO(xl): document
     *
     * @interface
     * @augments module:mpenc/helper/graph.CausalOrder
     * @augments module:mpenc/transcript.Messages
     * @memberOf module:mpenc/transcript
     */
    var Transcript = function() {
        throw new Error("cannot instantiate an interface");
    };

    /**
     * Add a message; all its parents must already have been added.
     *
     * @method
     * @param msg {module:mpenc/message.Message} Message to add.
     * @returns {Array.<string>} List of messages that became fully-acked by
     * the addition of this message, in some topological order. */
    Transcript.prototype.add;

    /**
     * The latest message before mId authored by the same author, or
     * <code>null</code> if mId is the first message authored by them.
     *
     * @method
     * @param mId {string} Message id.
     * @returns {?string} Latest preceding message id or <code>null</code>.
     */
    Transcript.prototype.pre_uId;

    /**
     * The latest message before mId authored by the given recipient of mId, or
     * <code>null</code> if they did not author any such messages.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a recipient of mId) to find message for.
     * @returns {?string} Latest preceding message id or <code>null</code>.
     * */
    Transcript.prototype.pre_ruId;

    /**
     * The earliest message after mId authored by the given recipient of mId, or
     * <code>null</code> we did not yet see them author such a message.
     *
     * @method
     * @param mId {string} Message id.
     * @param ruId {string} Author (a recipient of mId) to find message for.
     * @returns {?string} Earliest succeeding message id or <code>null</code>.
     */
    Transcript.prototype.suc_ruId;

    Object.freeze(Transcript.prototype);
    ns.Transcript = Transcript;

    return ns;
});
