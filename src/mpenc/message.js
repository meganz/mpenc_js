/**
 * @fileOverview
 * Message interfaces.
 */

define([
    "mpenc/helper/struct"
], function(struct) {
    "use strict";

    /**
     * @exports mpenc/message
     * Message interfaces.
     *
     * @description
     * Message interfaces.
     */
    var ns = {};

    /*
     * Created: 16 Feb 2015 Ximin Luo <xl@mega.co.nz>
     *
     * (c) 2015 by Mega Limited, Wellsford, New Zealand
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

    var Set = struct.ImmutableSet;

    /**
     * A set of Messages forming all or part of a session.
     *
     * @interface
     * @memberOf module:mpenc/message
     */
    var Message = function(mId, uId, pmId, ruId, secobj) {
        if (!(this instanceof Message)) return new Message(mId, uId, pmId, ruId, secobj);

        if (mId === null || mId === undefined) {
            throw new Error("invalid empty mId");
        }
        if (uId === null || uId === undefined) {
            throw new Error("invalid empty uId");
        }
        if (pmId === null || pmId === undefined) {
            throw new Error("invalid empty pmId");
        }
        if (ruId === null || ruId === undefined) {
            throw new Error("invalid empty ruId");
        }

        pmId = new Set(pmId);
        if (pmId.has(null) || pmId.has(undefined)) {
            throw new Error("invalid pmId: has empty value");
        }
        ruId = new Set(ruId);
        if (ruId.has(null) || ruId.has(undefined)) {
            throw new Error("invalid ruId: has empty value");
        }

        this.mId = mId;
        this.uId = uId;
        this.pmId = pmId;
        this.ruId = ruId;
        this.secobj = secobj;
    };

    /**
     * @method
     * @param mId {string} Message (node) id.
     * @returns {module:mpenc/message.Message} Message object for the id. */
    Message.prototype.members = function() {
        return this.ruId.union(new Set([this.uId]));
    };

    Object.freeze(Message.prototype);
    ns.Message = Message;

    return ns;
});
