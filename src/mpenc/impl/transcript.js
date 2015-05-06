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

define([
    "mpenc/helper/graph",
    "mpenc/helper/struct",
    "megalogger",
    "es6-collections",
], function(
    graph,
    struct,
    MegaLogger,
    es6_shim
) {
    "use strict";

    /**
     * @exports mpenc/impl/transcript
     * @description
     * Transcript implementation.
     */
    var ns = {};

    var MutableSet = Set; // TODO(xl): for some reason this doesn't work
    // even though the exact same thing is fine in struct.js, and we have to
    // instead resort to new Set().asMutable() below. investigate why...
    var Set = struct.ImmutableSet;
    var safeGet = struct.safeGet;
    var logger = MegaLogger.getLogger("transcript", undefined, "mpenc");

    /**
     * A set of BaseTranscript forming all or part of a session.
     *
     * @class
     * @memberOf module:mpenc/impl/transcript
     * @implements {module:mpenc/transcript.Transcript}
     */
    var BaseTranscript = function() {
        if (!(this instanceof BaseTranscript)) return new BaseTranscript();

        this._uIds = new Set();
        this._messages = new Map();
        this._minMessages = new Set();
        this._maxMessages = new Set();

        this._successors = new Map(); // mId: Set[mId], successors

        // overall sequence. only meaningful internally
        this._length = 0
        this._messageIndex = new Map(); // mId: int, index into _log
        this._log = [];

        // per-author sequence. only meaningful internally. like a local vector clock.
        this._authorMessages = new Map(); // uId: [mId], messages in the order they were authored
        this._authorIndex = new Map(); // mId: int, index into _authorMessages[mId's author]

        this._context = new Map(); // mId: uId: mId1, latest message sent by uId before mId, or null
        this._subsequent = new Map(); // mId: uId: (int, int), range of author-indexes of messages sent by
                                      // uId after mId, but before later messages sent by the same author
                                      // (0, 0) means we haven't seen uId speak at all yet

        this._unackby = new Map(); // mId: Set[uId], recipients of mId that we have not yet seen ack it
        this._unacked = new Set(); // Set[mId] of not fully-acked messages

        var self = this;
        this._merge = graph.createMerger(
            function(m) { return self.pre(m).toArray(); },
            function(m) { return self.suc(m).toArray(); },
            function(a, b) { return self.le(a, b); },
            function(m) { return self._messages.get(m).members(); },
            Set,
            function(p, a, b) { return p.merge(a, b); });
        this._fubar = false;

        this._cacheBy = new Map();
        this._cacheUnacked = null;
        this._invalidateCaches();
    };

    BaseTranscript.prototype._invalidateCaches = function(uId) {
        this._cacheUnacked = null;
        if (!uId) {
            this._cacheBy = new Map();
        } else {
            this._cacheBy.delete(uId);
        }
    };

    BaseTranscript.prototype._mergeContext = function(pmId, ruId) {
        var self = this;
        var context = new Map();
        pmId.forEach(function(m) {
            var mc = self._context.get(m);
            mc.forEach(function(um, u) {
                if (!context.has(u) || context.get(u) === null ||
                    (um !== null && self.ge(um, context.get(u)))) {
                    context.set(u, um);
                }
            });
        });
        pmId.forEach(function(m) { context.set(self.author(m), m); });
        ruId.forEach(function(u) { if (!context.has(u)) context.set(u, null); });
        context.forEach(function(_, pu) { if (!ruId.has(pu)) context.delete(pu); });
        return context;
    };

    BaseTranscript.prototype._sortMIds = function(mIds) {
        var self = this;
        mIds.sort(function(a, b) { return self._messageIndex.get(a) - self._messageIndex.get(b); });
        return mIds;
    };

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
        return safeGet(this._messages, mId).parents;
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
        } else if (this._messages.get(m1).recipients.has(u0)) {
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
        var init = safeGet(this._messages, mId).parents;
        var initArr = init.toArray();
        var self = this;
        return new Set(struct.iteratorToArray(graph.bfTopoIterator(init,
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
        )));
    };

    BaseTranscript.prototype.allAuthors = function() {
        return this._uIds;
    };

    BaseTranscript.prototype.author = function(mId) {
        return safeGet(this._messages, mId).author;
    };

    BaseTranscript.prototype.by = function(uId) {
        if (!this._cacheBy.has(uId)) {
            var msg = safeGet(this._authorMessages, uId).slice();
            Object.freeze(msg);
            this._cacheBy.set(uId, msg);
        }
        return this._cacheBy.get(uId);
    };

    // Messages

    BaseTranscript.prototype.get = function(mId) {
        return safeGet(this._messages, mId);
    };

    BaseTranscript.prototype.parents = BaseTranscript.prototype.pre;

    BaseTranscript.prototype.unackby = function(mId) {
        return safeGet(this._unackby, mId);
    };

    BaseTranscript.prototype.unacked = function() {
        if (!this._cacheUnacked) {
            var unacked = this._sortMIds(this._unacked.toArray());
            Object.freeze(unacked);
            this._cacheUnacked = unacked;
        }
        return this._cacheUnacked;
    };

    // Transcript

    BaseTranscript.prototype.add = function(msg) {
        if (this._fubar) {
            throw new Error("something horrible happened previously, refusing all operations");
        }

        var self = this;
        var mId = msg.mId, uId = msg.author, pmId = msg.parents, ruId = msg.recipients;
        // last message by the same author
        var pumId = this._authorMessages.has(uId)? this._authorMessages.get(uId).slice(-1)[0]: null;
        var pmIdArr = pmId.toArray();

        // sanity checks

        if (mId === null) {
            throw new Error("invalid mId: null");
        }

        if (pmId.has(mId)) {
            throw new Error("message references itself: " + mId + " in " + pmId);
        }

        if (this._messages.has(mId)) {
            throw new Error("message already added: " + mId);
        }

        if (uId === null) {
            throw new Error("invalid uId: null");
        }

        if (ruId.has(uId)) {
            throw new Error("message sent to self: " + uId + " in " + ruId);
        }

        if (ruId.size === 0) {
            // in principle, can support empty room talking to yourself
            logger.warn("message has no recipients: " + mId);
        }

        // ensure graph is complete, also preventing cycles
        var pmId404 = pmId.subtract(this._messages);
        if (pmId404.size > 0) {
            throw new Error("parents not found: " + pmId404);
        }

        // check sender is actually allowed to read the parents
        var pmId403 = pmIdArr.filter(function(pm) {
            return !self._messages.get(pm).members().has(uId);
        });
        if (pmId403.length > 0) {
            throw new Error("secret parents referenced: " + pmId403);
        }

        // check sanity of parents
        if (pmId.size >
            new Set(pmIdArr.map(function(m) { return self.author(m); })).size) {
            throw new Error("redundant parents: not from distinct authors");
        }

        // invariant: total-ordering of one user's messages
        // can't check mId directly since it's not in the graph yet, so check parents
        if (pumId !== null) {
            if (!pmIdArr.some(function(m) { return self.le(pumId, m); })) {
                throw new Error("" + mId + " does not reference prev-sent " + pumId);
            }
        }

        // merging the members checks they are in different chains, which ensures
        // transitive reduction and freshness consistency (see msg-notes)
        var merged = this._merge(pmId);

        var context = this._mergeContext(pmId, ruId);

        // update state
        // no turning back now; any exceptions raised from here onwards will lead
        // to inconsistent state and is a programming error.

        try {
            // update core
            var mIdS = new Set([mId]);
            this._uIds = this._uIds.union(new Set([uId]));
            this._messages.set(mId, msg);
            if (!pmId.size) {
                this._minMessages = this._minMessages.union(mIdS);
            }
            this._maxMessages = this._maxMessages.union(mIdS).subtract(pmId);

            // update successors
            pmId.forEach(function(m) {
                self._successors.set(m, self._successors.get(m).union(mIdS));
            });
            this._successors.set(mId, new Set());

            // update overall sequences
            this._messageIndex.set(mId, this._length);
            this._log.push(mId);
            this._length++;

            // update per-author sequences
            if (pumId === null) {
                this._authorMessages.set(uId, []);
            }
            this._authorMessages.get(uId).push(mId);
            var mSeq = this._authorMessages.get(uId).length - 1;
            this._authorIndex.set(mId, mSeq);

            // update context
            this._context.set(mId, context);
            context.forEach(function(um, _) {
               if (um === null) return;
               var subseq = self._subsequent.get(um).get(uId);
               var a = subseq[0], b = subseq[1];
               if (a === b) { // assert a == 0
                   a = mSeq
               }
               b = mSeq + 1;
               self._subsequent.get(um).set(uId, [a, b]);
            });
            this._subsequent.set(mId, new Map(ruId.toArray().map(function(ru) {
                return [ru, [0, 0]];
            })));

            // update unacked
            this._unackby.set(mId, ruId);
            this._unacked = this._unacked.union(mIdS);
            var ackthru = function(m) { return self._unackby.get(m).has(uId); };
            var anc = graph.bfIterator(pmIdArr.filter(ackthru), function(m) {
                return self.pre(m).toArray().filter(ackthru);
            });
            var acked = new Set().asMutable(); // TODO(xl): see note at top
            if (!ruId.size) {
                acked.add(mId);
            }
            struct.iteratorForEach(anc, function(am) {
                self._unackby.set(am, self._unackby.get(am).subtract(new Set([uId])));
                if (!self._unackby.get(am).size) {
                    acked.add(am);
                }
            });
            this._unacked = this._unacked.subtract(acked);
            acked = this._sortMIds(struct.iteratorToArray(acked.values()));

            this._invalidateCaches(uId);

            return acked;
        } catch (e) {
            this._fubar = true;
            throw e;
        }
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
            var subseq = safeGet(safeGet(this._subsequent, mId), ruId);
            var a = subseq[0], b = subseq[1];
            return (a === b)? null: this.by(ruId)[a];
        }
    };

    BaseTranscript.prototype.mergeMembers = function(parents) {
        return this._merge(parents);
    };

    Object.freeze(BaseTranscript.prototype);
    ns.BaseTranscript = BaseTranscript;


    return ns;
});
