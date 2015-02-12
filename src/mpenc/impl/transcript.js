/**
 * @fileOverview
 * Transcript implementation.
 */

define([
    "mpenc/helper/graph",
    "mpenc/helper/struct",
    "es6-collections"
], function(
    graph,
    struct,
    es6_shim
) {
    "use strict";

    /**
     * @exports mpenc/impl/transcript
     * Transcript implementation.
     *
     * @description
     * Transcript implementation.
     */
    var ns = {};

    var Set = struct.ImmutableSet;
    var safeGet = struct.safeGet;

    /*
     * Created: 10 Feb 2015 Ximin Luo <xl@mega.co.nz>
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

    /**
     * A set of BaseTranscript forming all or part of a session.
     *
     * @class
     * @memberOf module:mpenc/impl/transcript
     * @implements {module:mpenc/transcript.Transcript}
     */
    var BaseTranscript = function() {
        this._uIds = Set();
        this._messages = Map();
        this._minMessages = Set();
        this._maxMessages = Set();

        this._successors = Map(); // mId: Set[mId], successors

        // overall sequence. only meaningful internally
        this._length = 0
        this._messageIndex = Map(); // mId: int, index into _log
        this._log = [];

        // per-author sequence. only meaningful internally. like a local vector clock.
        this._authorMessages = Map(); // uId: [mId], messages in the order they were authored
        this._authorIndex = Map(); // mId: int, index into _authorMessages[mId's author]

        this._context = Map(); // mId: uId: mId1, latest message sent by uId before mId, or null
        this._subsequent = Map(); // mId: uId: (int, int), range of author-indexes of messages sent by
                                  // uId after mId, but before later messages sent by the same author

        this._unackby = Map(); // mId: Set[uId], recipients of mId that we have not yet seen ack it
        this._unacked = Set(); // Set[mId] of not fully-acked messages

        this._fubar = false;

        this._cacheBy = Map();
        this._cacheUnacked = null;
        this._invalidateCaches();
    };

    BaseTranscript.prototype._invalidateCaches = function(uId) {
        this._cacheUnacked = null;
        if (!uId) {
            this._cacheBy = Map();
        } else {
            this._cacheBy.delete(uId);
        }
    };

    BaseTranscript.prototype._mergeContext;

    // CausalOrder

    BaseTranscript.prototype.__defineGetter__("length", function() {
        return this._length;
    });

    BaseTranscript.prototype.all = function() {
        return this._log.slice(); // TODO: P- could be optimised with a cache
    };

    BaseTranscript.prototype.has = function(mId) {
        return this._messages.has(mId);
    };

    BaseTranscript.prototype.min = function() {
        return this._minMessages;
    };

    BaseTranscript.prototype.max = function() {
        return this._maxMessages;
    };

    BaseTranscript.prototype.pre = function(mId) {
        return safeGet(this._messages, mId).pmId;
    };

    BaseTranscript.prototype.suc = function(mId) {
        return safeGet(this._successors, mId);
    };

    BaseTranscript.prototype.le = function(m0, m1) {
        if (m0 === undefined || m1 === undefined) {
            throw new Error("le: m0 and m1 are not both defined: " + m0 + " vs " + m1);
        } else if (m0 === m1) {
            return true;
        }

        var u0 = this.author(m0);
        var u1 = this.author(m1);
        // author() throws if param doesn't exist, so no need to safeGet from here

        if (u0 === u1) {
            return this._authorIndex.get(m0) <= this._authorIndex.get(m1);
        } else if (this._messages.get(m1).ruId.has(u0)) {
            var p0 = this._context.get(m1).get(u0);
            return p0 !== null && this._authorIndex.get(m0) <= this._authorIndex.get(p0);
        } else {

            var i0 = this._messageIndex.get(m0);
            var i1 = this._messageIndex.get(m1);
            if (i0 > i1) {
                return false;
            } else {
                return this._le_expensive(m0, m1);
            }
        }
    };

    BaseTranscript.prototype._le_expensive = function(m0, m1) {
        // TODO: P- as per python prototype, this could be a BFS and/or cached,
        // but we optimise a lot already before we get to this stage so the
        // added complexity may not be worth it
        var pre = this.pre(m1).toArray();
        for (var i=0; i<pre.length; i++) {
            if (this.le(m0, pre[i])) {
                return true;
            }
        }
        return false;
    };

    BaseTranscript.prototype.ge = function(m0, m1) {
        return this.le(m1, m0);
    };

    BaseTranscript.prototype.pre_pred = function(mId, pred) {
        var init = safeGet(this._messages, mId).pmId;
        var initArr = init.toArray();
        var self = this;
        return Set(graph.bfTopoIterator(init,
            function(mId) { return self.pre(mId); },
            function(mId) {
                // limit traversal to ancestors of init
                return self.suc(mId).toArray().filter(function(nmId) {
                    return initArr.some(function(pm) {
                        return self.le(nmId, pm);
                    });
                });
            },
            function(mId) { return !pred(mId); },
            true
        ));
    };

    BaseTranscript.prototype.allAuthors = function() {
        return this._uIds;
    };

    BaseTranscript.prototype.author = function(mId) {
        return safeGet(this._messages, mId).uId;
    };

    BaseTranscript.prototype.by = function(uId) {
        if (!this._cacheBy.has(uId)) {
            var msg = safeGet(this._authorMessages, uId).slice();
            Object.freeze(msg);
            this._cacheBy.set(uId, msg);
        }
        return this._cacheBy.get(uId);
    };

    // MessageLog

    BaseTranscript.prototype.get = function(mId) {
        return safeGet(this._messages, mId);
    };

    BaseTranscript.prototype.parents = BaseTranscript.prototype.pre;

    BaseTranscript.prototype.unackby = function(mId) {
        return safeGet(this._unackby, mId);
    };

    BaseTranscript.prototype.unacked = function() {
        if (!this._cacheUnacked) {
            var unacked = this._unacked.toArray();
            // sort in add-order
            var self = this;
            unacked.sort(function(a, b) { return self._messageIndex(a) - self._messageIndex(b); });
            Object.freeze(unacked);
            this._cacheUnacked = unacked;
        }
        return this._cacheUnacked;
    };

    // Transcript

    BaseTranscript.prototype.add = function(msg) {
        throw new Error("not implemented");
    };

    BaseTranscript.prototype.pre_uId = function(mId) {
        var i = safeGet(this._authorIndex, mId);
        var uId = this.author(mId);
        return (i)? this._authorMessages.get(uId)[i]: null;
    };

    BaseTranscript.prototype.pre_ruId = function(mId, ruId) {
        if (ruId === undefined) {
            return new Map(safeGet(this._context, mId).entries());
        } else {
            return safeGet(safeGet(this._context, mId), ruId);
        }
    };

    BaseTranscript.prototype.suc_ruId = function(mId, ruId) {
        if (ruId === undefined) {
            throw new Error("not implemented");
        } else {
            var a = safeGet(safeGet(this._subsequent, mId), ruId)[0];
            var by = this.by(ruId);
            return (by.length > a)? by[a]: null;
        }
    };

    Object.freeze(BaseTranscript.prototype);
    ns.BaseTranscript = BaseTranscript;


    return ns;
});
