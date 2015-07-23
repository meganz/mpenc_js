/*
 * Created: 28 Mar 2014 Ximin Luo <xl@mega.co.nz>
 * Contributions: Guy Kloss <gk@mega.co.nz>
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
    "mpenc/helper/utils",
    "es6-collections",
    "megalogger",
], function(utils, es6_shim, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/helper/struct
     * @description
     * Data structures.
     */
    var ns = {};

    var logger = MegaLogger.getLogger('struct', undefined, 'helper');

    /**
     * 3-arg function to iterate over a Collection
     * @callback forEachCallback
     * @param key {} In the case of Set, this is the same as the value.
     * @param value {}
     * @param collection {}
     */

    /**
     * Wrapper around a "get()"-capable object (e.g. Map) that throws
     * <code>ReferenceError</code> when the result is <code>undefined</code>.
     *
     * @memberOf! module:mpenc/helper/struct
     */
    var safeGet = function(gettable, key) {
        var result = gettable.get(key);
        if (result === undefined) {
            throw new ReferenceError("invalid key: " + key);
        }
        return result;
    };
    ns.safeGet = safeGet;

    /**
     * Force an iterable or iterator into an iterator.
     *
     * @param iter {(Iterable|Iterator)} Iterable to unwrap or Iterator
     * @returns {Iterator}
     * @memberOf! module:mpenc/helper/struct
     */
    var toIterator = function(iter) {
        if (typeof Symbol !== "undefined" && iter[Symbol.iterator]) {
            return iter[Symbol.iterator](); // assume already iterator
        } else if ("@@iterator" in iter) {
            return iter["@@iterator"]();
        } else if ("next" in iter) {
            return iter;
        } else if (iter instanceof Array) {
            // polyfill in for older JS that doesn't have Array implement Iterable
            // only works when array is not mutated during iteration
            var i = 0;
            return { next: function() { return { done: i>=iter.length, value: iter[i++] }; } };
        } else {
            throw new Error("not an iterable or iterator: " + iter);
        }
    };
    ns.toIterator = toIterator;

    /**
     * Apply a function to an ES6 iterator, ignoring its "return value".
     *
     * @param iter {Iterator} Iterator to run through.
     * @param func {function} 1-arg function to apply to each element.
     * @memberOf! module:mpenc/helper/struct
     */
    var iteratorForEach = function(iter, func) {
        // work around https://github.com/WebReflection/es6-collections/issues/22
        if (iter instanceof Array) { return iter.forEach(func); }
        var done = false;
        while (!done) {
            var result = iter.next();
            done = result.done;
            if (!done) {
                func(result.value);
            } else {
                return result.value;
            }
        }
    };
    ns.iteratorForEach = iteratorForEach;

    /**
     * Populate an array using an ES6 iterator, ignoring its "return value".
     *
     * @param iter {Iterator} Iterator to run through.
     * @returns {Array} Yielded values of the iterator.
     * @memberOf! module:mpenc/helper/struct
     */
    var iteratorToArray = function(iter) {
        var a = [];
        iteratorForEach(iter, function(v) { a.push(v); });
        return a;
    };
    ns.iteratorToArray = iteratorToArray;


    var _setPropertyAlias = function(cls, alias, prop) {
        Object.defineProperty(cls.prototype, alias, {
            get: function() { return this[prop]; },
            set: function(v) { this[prop] = v; }
        });
    };

    /**
     * Create a class that represents an immutable tuple with named fields.
     *
     * Similar to collections.namedtuple in Python. One may access the fields
     * either by name or by numerical index.
     *
     * <pre>
     * > var Point = createTupleClass("x", "y");
     * undefined
     * > var treasure = Point(2, 3);
     * undefined
     * > treasure
     * { '0': 2,
     *   '1': 3,
     *   length: 2 }
     * > treasure.x
     * 2
     * > treasure.y
     * 3
     * > treasure instanceof Point
     * true
     * > treasure instanceof Array
     * true
     * > Point.prototype.d = function() { return Math.sqrt(this.x*this.x + this.y*this.y); };
     * > treasure.d()
     * 3.605551275463989
     * </pre>
     *
     * @param [baseClass] {object} Optional parent class to extend from; this
     *      itself must be a subclass of Array. If omitted, defaults to Array.
     * @param fieldNames {...string} Names of fields to alias to each numerical
     *      index within the tuple.
     * @returns {function} A constructor. You may define a 0-arg method on it
     *      as <code>YourClass.prototype._postInit</code>, which will be
     *      called automatically by the constructor. This is useful to e.g.
     *      check inputs, perform further initialisation, etc. The constructor
     *      also has a pre-defined <code>equals</code> method which shallow
     *      compares against another tuple, using <code>item.equals</code>
     *      where available, otherwise falling back to <code>===</code>.
     * @memberOf! module:mpenc/helper/struct
     */
    var createTupleClass = function() {
        var fields = Array.prototype.slice.call(arguments);
        var baseClass = Array;
        if (fields[0] && typeof fields[0] !== "string") {
            if (fields[0].prototype instanceof Array) {
                baseClass = fields.shift();
            } else {
                throw new Error("first arg must be string or subclass of Array");
            }
        }
        var cls = function() {
            if (!(this instanceof cls)) {
                var args = Array.prototype.concat.apply([undefined], arguments);
                return new (Function.prototype.bind.apply(cls, args))();
            }
            for (var i = 0; i < arguments.length; i++) {
                this[i] = arguments[i];
            }
            this.length = arguments.length;
            Object.freeze(this);
            if (this._postInit) {
                this._postInit();
            }
        };
        cls.prototype = Object.create(baseClass.prototype);
        cls.prototype.constructor = cls;
        for (var i = 0; i < fields.length; i++) {
            _setPropertyAlias(cls, fields[i], i);
        }
        cls.prototype.equals = function(other) {
            if (typeof other !== "object" || other === null ||
                !(other instanceof cls) && !(this instanceof other.constructor)) {
                return false;
            }
            for (var i = 0; i < fields.length; i++) {
                var a = this[i];
                var b = other[i];
                var eq = (typeof a === "object" && "equals" in a) ? a.equals(b) : a === b;
                if (!eq) {
                    return false;
                }
            }
            return true;
        };
        return cls;
    };
    ns.createTupleClass = createTupleClass;


    /**
     * An immutable set, implemented using the ES6 mutable <code>Set</code>
     * (or else a shim in browsers that don't support this).
     *
     * <p>Equality in equals() is taken strictly, using <code>===</code>.</p>
     *
     * <p>Otherwise, the API is intended to match Facebook's <a
     * href="https://github.com/facebook/immutable-js/">Immutable JS</a>
     * library. We don't use that, because it is 42KB and we only need Set.</p>
     *
     * <p>The shim (from es6-shim) does not scale to massive sizes, but should
     * be adequate for representing (e.g.) members of a chat.</p>
     *
     * @class
     * @param iterable {Iterable} Elements of the set
     * @memberOf! module:mpenc/helper/struct
     */
    var ImmutableSet = function(iterable) {
        if (!(this instanceof ImmutableSet)) {
            return new ImmutableSet(iterable);
        }

        var items = new Set(iterable);

        // Facebook ImmutableSet provides length
        this.length = items.size;
        this.size = items.size;

        // adhere to the Iterable interface if available
        if (typeof Symbol !== "undefined") {
            // ES6 current standard
            this[Symbol.iterator] = function() {
                return items[Symbol.iterator]();
            };
        } else if ("@@iterator" in items) {
            // at time of writing, Firefox ESR (31) uses an older syntax
            // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...of#Browser_compatibility
            this["@@iterator"] = function() {
                return items["@@iterator"]();
            };
        }

        /**
         * Apply a function to every member. The callback is the same as Set.
         * @param callback {forEachCallback} Function to execute for each element.
         * @param thisObj {} Value to use as <code>this</code> when executing <code>callback</code>.
         */
        this.forEach = function(callback, thisObj) {
            return items.forEach(function(v, v0, a) {
                // prevent external access to mutable set
                return callback.call(thisObj, v, v0, this);
            });
        };

        /**
         * Return a Iterator of the elements contained in this set.
         */
        this.values = function() {
            return items.values();
        };

        /**
         * Whether the set contains the given element.
         * @returns {boolean}
         */
        this.has = function(elem) {
            return items.has(elem);
        };
    };

    /**
     * Return a sorted array representation of this set.
     * @returns {Array}
     */
    ImmutableSet.prototype.toArray = function() {
        var a = [];
        this.forEach(function(v) { a.push(v); });
        a.sort();
        return a;
    };

    /**
     * Return a string representation of this set.
     * @returns {string}
     */
    ImmutableSet.prototype.toString = function() {
        return "ImmutableSet(" + this.toArray() + ")";
    };

    /**
     * Return a mutable copy of this set.
     * @returns {Set}
     */
    ImmutableSet.prototype.asMutable = function() {
        return new Set(this);
    };

    /**
     * Return whether this set equals another set.
     * @param {module:mpenc/helper/struct.ImmutableSet} other
     * @returns {boolean}
     */
    ImmutableSet.prototype.equals = function(other) {
        if (!other || other.size !== this.size) {
            return false;
        }
        var eq = true;
        this.forEach(function(v) {
            if (!other.has(v)) {
                eq = false;
            }
        });
        return eq;
    };

    /**
     * Return the disjunction of this and another set, i.e. elements that
     * are in this <b>or</b> the other set.
     * @param {module:mpenc/helper/struct.ImmutableSet} other
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     */
    ImmutableSet.prototype.union = function(other) {
        var union = other.asMutable();
        this.forEach(function(v) {
            union.add(v);
        });
        return new ImmutableSet(union);
    };

    /**
     * Return the conjunction of this and another set, i.e. elements that
     * are in this <b>and</b> the other set.
     * @param {module:mpenc/helper/struct.ImmutableSet} other
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     */
    ImmutableSet.prototype.intersect = function(other) {
        var intersection = new Set();
        this.forEach(function(v) {
            if (other.has(v)) {
                intersection.add(v);
            }
        });
        return new ImmutableSet(intersection);
    };

    /**
     * Return the difference of this and another set, i.e. elements that
     * are in this <b>and not</b> the other set.
     * @param {module:mpenc/helper/struct.ImmutableSet} other
     * @returns {module:mpenc/helper/struct.ImmutableSet}
     */
    ImmutableSet.prototype.subtract = function(other) {
        var difference = this.asMutable();
        this.forEach(function(v) {
            if (other.has(v)) {
                difference.delete(v);
            }
        });
        return new ImmutableSet(difference);
    };

    /**
     * Return what was [added, removed] between this and another set, i.e.
     * same as [other.subtract(this), this.subtract(other)].
     * @param {module:mpenc/helper/struct.ImmutableSet} newer
     * @returns {module:mpenc/helper/struct.ImmutableSet[]}
     */
    ImmutableSet.prototype.diff = function(newer) {
        return [newer.subtract(this), this.subtract(newer)];
    };

    /**
     * Apply a difference to an older set.
     *
     * @param diff {module:mpenc/helper/struct.ImmutableSet[]} 2-tuple of what to (add, remove).
     * @returns {module:mpenc/helper/struct.ImmutableSet} Newer set
     */
    ImmutableSet.prototype.patch = function(diff) {
        if (!diff || diff[0].intersect(diff[1]).size > 0) {
            throw new Error("invalid diff: " + diff);
        }
        return this.union(diff[0]).subtract(diff[1]);
    };

    /**
     * Do a 3-way merge between this parent set and two child sets.
     * @param {module:mpenc/helper/struct.ImmutableSet} first child
     * @param {module:mpenc/helper/struct.ImmutableSet} other child
     * @returns {module:mpenc/helper/struct.ImmutableSet} Result set
     */
    ImmutableSet.prototype.merge = function(child0, child1) {
        return child1.union(child0.subtract(this)).subtract(this.subtract(child0));
    };

    /**
     * Empty immutable set.
     */
    ImmutableSet.EMPTY = new ImmutableSet();

    /**
     * Empty diff between immutable sets.
     */
    ImmutableSet.EMPTY_DIFF = [ImmutableSet.EMPTY, ImmutableSet.EMPTY];

    /**
     * Coerce something into an ImmutableSet if possible.
     *
     * If the input is already an ImmutableSet, it is returned. Falsy inputs
     * return ImmutableSet.EMPTY, otherwise we pass it through the constructor.
     */
    ImmutableSet.from = function(v) {
        return (v instanceof ImmutableSet) ? v :
            v ? new ImmutableSet(v) : ImmutableSet.EMPTY;
    };

    Object.freeze(ImmutableSet.prototype);
    ns.ImmutableSet = ImmutableSet;


    /**
     * @param iterables {...Object} An Iterable or an object with a
     *      <code>forEach</code> method.
     * @returns {boolean} Whether the given iterables are disjoint.
     */
    ns.isDisjoint = function() {
        var args = Array.prototype.slice.call(arguments);
        var counter = 0;
        var union = new Set();
        var add = function(v) { union.add(v); counter++; };
        for (var i = 0; i < args.length; i++) {
            var it = args[i];
            if ("forEach" in it) {
                it.forEach(add);
            } else {
                struct.iteratorForEach(it, add);
            }
        }
        return union.size === counter;
    };

    /**
     * A TrialTarget is an object implementing some interface methods that a
     * {@link TrialBuffer} operates on.
     *
     * @interface
     * @memberOf module:mpenc/helper/struct
     */
    var TrialTarget = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * This method performs the actual trial.
     *
     * @param pending {boolean}
     *     Set to `true` if the params are already on the queue (i.e. was seen
     *     before). Note: `false` does not necessarily mean it was *never* seen
     *     before - it may have been dropped since then.
     * @param param {object}
     *     The parameter to test against this trial function.
     * @returns {boolean}
     *     `true` if processing succeeds, otherwise `false`.
     */
    TrialTarget.prototype.tryMe;

    /**
     * This method determines the buffer capacity. It takes no parameters.
     *
     * @returns {integer}
     *     Number of allowed elements in the buffer.
     */
    TrialTarget.prototype.maxSize;

    /**
     * This method determines a parameter's identifier.
     *
     * @param param {object}
     *     The parameter to find an identifier for.
     * @returns {string}
     *     Identifier that can be used as the key in an {object} to index the
     *     parameters in the buffer, usually a {string}.
     */
    TrialTarget.prototype.paramId;

    /**
     * Optional method; called when a param object is removed from the queue
     * without having been accepted by a trial function. For example, to clean
     * up secrets that were stored in sensitive memory.
     *
     * If a param object is removed from the queue after being accepted by
     * a trial function, this method is <b>not</b> called.
     *
     * @param replace {boolean} <code>true</code> if the param is being removed
     *      due to an incoming duplicate (which may be stored in another part
     *      of memory), or <code>false</code> if it is being removed entirely.
     * @param param {object}
     *     The object that was removed or replaced.
     */
    TrialTarget.prototype.cleanup;

    Object.freeze(TrialTarget.prototype);
    ns.TrialTarget = TrialTarget;
    // jshint +W030


    /**
     * A TrialBuffer holds data items ("parameters") that failed to be accepted
     * by a trial function, but that may later be acceptable when newer
     * parameters arrive and are themselves accepted.
     *
     * <p>If the buffer goes above capacity, the oldest item is automatically
     * dropped without being tried again.</p>
     *
     * @constructor
     * @param name {string}
     *     Name for this buffer, useful for debugging.
     * @param target {TrialTarget}
     *     An object satisfying the TrialTarget interface, to apply trials to.
     * @param drop {boolean}
     *     Whether to drop items that overflow the buffer according to
     *     #maxSize, or merely log a warning that the buffer is over
     *     capacity (optional, default: true).
     * @returns {module:mpenc/helper/struct.TrialBuffer}
     * @memberOf! module:mpenc/helper/struct#
     *
     * @property name {string}
     *     Name of trial buffer.
     * @property target {TrialTarget}
     *     An object satisfying the TrialTarget interface, to apply trials to.
     * @property drop {boolean}
     *     Whether to drop parameters beyond the sizing of the buffer.
     */
    var TrialBuffer = function(name, target, drop) {
        this.name = name || '';
        this.target = target;
        this.drop = drop === undefined ? true : drop;
        this._cleanup = target.cleanup ? target.cleanup.bind(target) : function() {};
        this._buffer = new Map();
    };
    ns.TrialBuffer = TrialBuffer;

    /**
     * Size of trial buffer.
     *
     * @returns {integer}
     */
    TrialBuffer.prototype.length = function() {
        return this._buffer.size;
    };

    /**
     * Get the currently queued items.
     *
     * @returns {Array}
     */
    TrialBuffer.prototype.queue = function() {
        return iteratorToArray(this._buffer.values());
    };

    /**
     * Retry all the currently queued items.
     *
     * <p>One should not need to call this in most circumstances, unless state
     * changes can happen outside of <code>trial()</code>, that could make
     * previously queued items acceptable by the trial function even though
     * they weren't accepted before.</p>
     */
    TrialBuffer.prototype.retryAll = function() {
        // This is a bit inefficient when params have a known dependency
        // structure such as in the try-accept buffer; however we think the
        // additional complexity is not worth the minor performance gain.
        // Also, the try-decrypt buffer does not have such structure and
        // there we *have* to brute-force it.
        var hadSuccess = true;
        var self = this;
        var tryAndDelete = function(item, id) {
            if (self.target.tryMe(true, item)) {
                self._buffer.delete(id);
                logger.debug(self.name + ' unstashed ' + btoa(id));
                hadSuccess = true;
            }
        };
        while (hadSuccess) {
            hadSuccess = false;
            this._buffer.forEach(tryAndDelete);
        }
    };

    TrialBuffer.prototype._dropExtra = function() {
        var maxSize = this.target.maxSize();
        if (this._buffer.size > maxSize) {
            if (this.drop) {
                var droppedID = this._buffer.keys().next().value;
                var dropped = this._buffer.get(droppedID);
                this._buffer.delete(droppedID);
                this._cleanup(false, dropped);
                logger.warn(this.name + ' DROPPED ' + btoa(droppedID) +
                            ' at size ' + maxSize + ', potential data loss.');
                logger.warn(dropped);
            } else {
                logger.info(this.name + ' is '
                            + (this._buffer.size - maxSize)
                            + ' items over expected capacity.');
            }
        }
    };

    /**
     * Try to accept a parameter, stashing it in the buffer if this fails.
     * If it succeeds, also try to accept previously-stashed parameters.
     *
     * @param param {object}
     *      Parameter to be tried.
     * @param [keepCurrent] {boolean}
     *      Whether to keep it at its current place in the queue (if it is
     *      already there). Default: <code>false</code>, i.e. move to front.
     * @returns {boolean}
     *      Whether the processing succeeded.
     */
    TrialBuffer.prototype.trial = function(param, keepCurrent) {
        keepCurrent = keepCurrent || false;
        var paramID = this.target.paramId(param);
        var pending = this._buffer.has(paramID);
        var olddupe = undefined;
        if (pending === true) {
            olddupe = this._buffer.get(paramID);
            var olddupeID = this.target.paramId(olddupe);
            if (olddupeID !== paramID) {
                throw new Error('paramId gave inconsistent results');
            }
        }

        if (this.target.tryMe(pending, param)) {
            this._buffer.delete(paramID);
            this.retryAll();
            return true;
        } else {
            if (pending) {
                if (!keepCurrent) {
                    this._buffer.delete(paramID);
                    this._cleanup(true, olddupe);
                    this._buffer.set(paramID, param);
                    logger.debug(this.name + ' restashed ' + btoa(paramID));
                }
            } else {
                this._buffer.set(paramID, param);
                logger.debug(this.name + ' stashed ' + btoa(paramID));
                this._dropExtra();
            }
            return false;
        }
    };

    /**
     * Trial target with a timeout.
     *
     * Use this to wrap a trial target, to automatically call an errback if
     * the param stays unaccepted for too long.
     *
     * @class
     * @memberOf module:mpenc/helper/struct
     * @implements {module:mpenc/helper/struct.TrialTarget}
     * @param timer {module:mpenc/helper/async.Timer} Timer to run the timeout.
     * @param timeout {number} Timer ticks to set the timeout to.
     * @param errback {function} 1-arg function, takes a param object and
     *      called on expiry of the timeout.
     * @param target {module:mpenc/helper/struct.TrialTarget} Target to wrap.
     */
    var TrialTimeoutTarget = function(timer, timeout, errback, target) {
        this._timer = timer;
        this._timeout = timeout;
        this._errback = errback;
        this._target = target;
        this._timeouts = new Map();
    };

    TrialTimeoutTarget.prototype.tryMe = function(pending, param) {
        var success = this._target.tryMe(pending, param);
        var paramId = this._target.paramId(param);
        if (!success && !pending && !this._timeouts.has(paramId)) {
            var self = this;
            var timeout = function() {
                self._errback(param);
                self._timeouts.delete(paramId);
            };
            var cancel = this._timer.after(this._timeout, timeout);
            this._timeouts.set(paramId, cancel);
        }
        if (success && this._timeouts.has(paramId)) {
            this._timeouts.get(paramId)(); // cancel timeout when it succeeds
            this._timeouts.delete(paramId);
        }
        return success;
    };

    TrialTimeoutTarget.prototype.maxSize = function() {
        return this._target.maxSize();
    };

    TrialTimeoutTarget.prototype.paramId = function(param) {
        return this._target.paramId(param);
    };

    TrialTimeoutTarget.prototype.cleanup = function(replace, param) {
        if (this._target.cleanup) {
            return this._target.cleanup(replace, param);
        }
    };

    Object.freeze(TrialTimeoutTarget.prototype);
    ns.TrialTimeoutTarget = TrialTimeoutTarget;


    return ns;
});
