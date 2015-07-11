/*
 * Created: 30 Mar 2015 Ximin Luo <xl@mega.co.nz>
 *
 * (c) 2015 by Mega Limited, Auckland, New Zealand
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
    "mpenc/helper/struct",
    "es6-collections",
    "promise-polyfill",
    "megalogger"
], function(assert, struct, es6_shim, Promise, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/helper/async
     * @description
     * Utilities for asynchronous programming.
     */
    var ns = {};

    var ImmutableSet = struct.ImmutableSet;

    var logger = MegaLogger.getLogger("async");
    var _assert = assert.assert;

    /**
     * 0-arg function to cancel a subscription; does not throw an exception.
     *
     * @callback canceller
     * @returns {boolean} <code>false</code> if already cancelled, otherwise
     *     <code>true</code>.
     */

    /**
     * 1-arg function to handle items published as part of a subscription.
     *
     * @callback subscriber
     * @param item {object} The published item
     * @returns {object} An optional "status" to give back to the publisher.
     *      See {module:mpenc/helper/async.Observable#publish} for details.
     */

    /**
     * 1-arg function for registering subscribers to future published items.
     *
     * @callback subscribe
     * @param subscriber {module:mpenc/helper/async~subscriber}
     * @returns canceller {module:mpenc/helper/async~canceller}
     * @see module:mpenc/helper/async.Observable
     * @see module:mpenc/helper/async.Observable#subscribe
     */

    /**
     * Throw an Error, or return a non-Error.
     *
     * Useful for Promise callbacks that act like "finally" cleanups, where you
     * register it as p.then(cb, cb) to call on both fulfillment and rejection.
     */
    ns.exitFinally = function(r) {
        if (r instanceof Error) {
            throw r;
        } else {
            return r;
        }
    };


    /**
     * Create a new <code>Promise</code> and return its <code>resolve</code>,
     * <code>reject</code> write capabilities back to the caller.
     *
     * @return {{ promise: Promise, resolve: function, reject: function }}
     *      The promise together with its write capabilities.
     */
    ns.newPromiseAndWriters = function() {
        var resolve, reject;
        var p = new Promise(function(rs, rj) {
            resolve = rs;
            reject = rj;
        });
        return { promise: p, resolve: resolve, reject: reject };
    };


    /**
     * A subscribe-function with child tweaked subscribe-functions.
     *
     * This is not instantiable directly; use Subscribe.wrap() instead.
     *
     * @class
     * @memberOf module:mpenc/helper/async
     * @see module:mpenc/helper/async~subscribe
     */
    var Subscribe = function() {
        throw new Error("cannot instantiate; use Subscribe.wrap() instead.");
    };

    /**
     * Decorate a plain subscribe-function with child tweaks.
     *
     * @param subscribe {module:mpenc/helper/async~subscribe}
     * @returns {module:mpenc/helper/async~subscribe}
     */
    Subscribe.wrap = function(subscribe) {
        // a slight hack here to support some nicer syntax for clients
        if (subscribe instanceof Subscribe) {
            return subscribe;
        } else if (!(subscribe instanceof Function)) {
            throw new Error("tried to wrap non-function: " + subscribe);
        } else if (Object.setPrototypeOf) {
            Object.setPrototypeOf(subscribe, Subscribe.prototype);
        } else {
            subscribe.__proto__ = Subscribe.prototype; // jshint ignore:line
        }
        Object.freeze(subscribe);
        return subscribe;
    };

    Subscribe.prototype = Object.create(Function.prototype);

    /**
     * A subscribe-function that registers once-only subscriptions.
     *
     * As soon as an item is published to the subscription, it is cancelled and
     * no more items are published to it.
     *
     * @member
     * @type {module:mpenc/helper/async~subscribe}
     */
    Subscribe.prototype.once = function(sub) {
        var cancel;
        var wrapped_sub = function(item) {
            cancel();
            return sub(item);
        };
        cancel = this(wrapped_sub);
        return cancel;
    };

    /**
     * A subscribe-function that registers until-true subscriptions.
     *
     * As soon as a subscription returns <code>true</code>, it is cancelled and
     * no more items are published to it.
     *
     * @member
     * @type {module:mpenc/helper/async~subscribe}
     */
    Subscribe.prototype.untilTrue = function(sub) {
        var cancel;
        var wrapped_sub = function(item) {
            var r = sub(item);
            if (r === true) {
                cancel();
            }
            return r;
        };
        cancel = this(wrapped_sub);
        return cancel;
    };

    /**
     * A subscribe-function that registers subscriptions with a secondary
     * backup subscription fired from a different context.
     *
     * If the primary subscription is fired first or cancelled, the secondary
     * subscription is also cancelled. If the secondary subscription is fired
     * first, the primary one is cancelled, but allowRecover overrides this.
     *
     * @param backup {module:mpenc/helper/async~subscribe}
     *      Subscribe-function for the secondary item/event.
     * @param bSub {module:mpenc/helper/async~subscriber}
     *      Subscriber to call if the secondary subscription fires.
     * @param allowRecover {boolean} Allow the primary subscription to fire,
     *      even if the secondary subscription is fired first.
     * @returns {module:mpenc/helper/async~subscribe} Tweaked subscribe-function
     */
    Subscribe.prototype.withBackup = function(backup, bSub, allowRecover) {
        var self = this;
        return function(sub) {
            var cancel;
            var realbSub = (allowRecover)? bSub: function() {
                cancel();
                return bSub();
            };
            var cancelErr = backup(realbSub);
            var wrapped_sub = function(item) {
                cancelErr();
                return sub(item);
            };
            cancel = self(wrapped_sub);
            return function() {
                cancelErr();
                return cancel();
            };
        };
    };

    Object.freeze(Subscribe.prototype);
    ns.Subscribe = Subscribe;


    var SubscriptionReentry = {
        NOADD_REM: 1,
        ADD_REM: 3,
        DEFAULT: 1,
    };


    /**
     * An Observable.
     *
     * This is used generally to implement asynchronous pipelines, where you
     * want to pass items to unspecified components, but are not directly
     * interested in getting a response back for each items you pass on. This
     * is in contrast to Future/Promise, whose purpose is to represent any
     * eventual response or lack of it.
     *
     * It is recommended for the publisher (the entity that created/owns this
     * object), to make sub(), the "read capability", accessible to clients,
     * but keep pub(), the "write capability", private. This pattern is also
     * found in many Future-Promise designs.
     *
     * If a subscription is registered during the publishing of an item on the
     * same Observable, it will *not* be fired in the current publishing, and
     * will not receive the item. However if a subscription is cancelled during
     * this time, then it will not be fired either, even if it was due to be
     * fired later. (This is identical to how events are handled on browsers.)
     *
     * @class
     * @param {boolean} require_subs Elements of the set
     * @memberOf module:mpenc/helper/async
     */
    var Observable = function(require_subs, subscriptionReentry) {
        if (!(this instanceof Observable)) {
            return new Observable(require_subs);
        }

        var _subs = new Map();
        var _subn = 0;
        var _require_subs = require_subs;

        /**
         * Subscribe to new items published in the future.
         *
         * The same subscriber function may be registered multiple times; each
         * registration is treated as a *separate* subscription, to be fired
         * and/or cancelled individually.
         *
         * @method
         * @param subscriber {module:mpenc/helper/async~subscriber}
         * @returns canceller {module:mpenc/helper/async~canceller}
         */
        this.subscribe = Subscribe.wrap(function(sub) {
            if (!(sub instanceof Function)) {
                throw new Error("tried to subscribe non-function: " + sub);
            }
            _subs.set(_subn, sub);
            var k = _subn;
            _subn += 1;
            return function() {
                return _subs.delete(k);
            };
        });

        subscriptionReentry = (subscriptionReentry === undefined)? SubscriptionReentry.DEFAULT: subscriptionReentry;
        var iterSubs;
        switch (subscriptionReentry) {
        case SubscriptionReentry.NOADD_REM:
            iterSubs = function() { return new Map(struct.iteratorToArray(_subs.entries())); }; // should just be new Map(_subs) in ES6
            break;
        case SubscriptionReentry.ADD_REM:
            iterSubs = function() { return _subs; };
            break;
        default:
            throw new Error("unsupported SubscriptionReentry: " + subscriptionReentry);
        }

        /**
         * Publish an item to all subscriptions.
         *
         * Subscriptions are fired in the order in which they were registered.
         *
         * @returns status {Array} An array of status objects that each
         *      subscriber returned. The semantics of these objects is defined
         *      by the publisher, who should make this clear in its contract.
         *      Typically, this could just be a boolean that represents whether
         *      the published item was accepted by the subscriber. It should
         *      probably *not* represent the "result" of any operation, even as
         *      a Future[result], since this class is designed for situations
         *      where the publisher doesn't care about such things.
         */
        this.publish = function(item) {
            if (_require_subs && !_subs.size) {
                throw new Error("published item with no subscriber: " + item);
            }
            var status = [];
            iterSubs().forEach(function(sub, k) {
                if (!_subs.has(k)) { return; } // don't call if removed by previous sub
                try {
                    status.push(sub(item));
                } catch (e) {
                    __SubscriberFailure_publishGlobal(sub, item, e);
                    status.push(undefined);
                }
            });
            return status;
        };

        this.size = function() {
            return _subs.size;
        };
    };
    ns.Observable = Observable;


    /**
     * A subscriber failed to handle an item or event.
     *
     * @class
     * @memberOf module:mpenc/helper/async
     */
    var SubscriberFailure = function(sub, item, error) {
        if (!(this instanceof SubscriberFailure)) {
            return new SubscriberFailure(sub, item, error);
        }
        this.sub = sub;
        this.item = item;
        this.error = error;
    };

    var __SubscriberFailure_global = new Observable();

    var __SubscriberFailure_publishGlobal = function(sub, item, error) {
        if (item instanceof SubscriberFailure) {
            logger.log(MegaLogger.LEVELS.WARN, "swallowed recursive SubscriberFailure: " + sub + ", " + item + ", " + error);
        } else {
            __SubscriberFailure_global.publish(new SubscriberFailure(sub, item, error));
        }
    };

    /**
     * Subscribe to all subscriber failures in the entire program.
     */
    SubscriberFailure.subscribeGlobal = __SubscriberFailure_global.subscribe;

    var _toString = function(x) {
        try {
            return "" + x;
        } catch(e) {
            // work around PhantomJS deficiency
            return JSON.stringify(x);
        }
    };

    /**
     * Stop logging all subscriber failures in the entire program.
     */
    SubscriberFailure.cancelGlobalLog = __SubscriberFailure_global.subscribe(function(f) {
        logger.warn("subscriber (" + f.sub +
            ") failed on (" + _toString(f.item) + "): " + f.error +
            "; stack trace: ");
        logger.warn(f.error.stack);
    });

    ns.SubscriberFailure = SubscriberFailure;


    /**
     * Combine several cancellers into a single canceller.
     *
     * @param cancels {module:mpenc/helper/async~canceller[]}
     * @returns {module:mpenc/helper/async~canceller}
     * @memberOf module:mpenc/helper/async
     */
    var combinedCancel = function(cancels) {
        return function() {
            var retval = false;
            var error = null;
            for (var i=0; i<cancels.length; i++) {
                var c = cancels[i];
                try {
                    retval |= c();
                } catch (e) {
                    // not supposed to throw, but if it does, we make sure
                    // everything else is still cancelled
                    error = e;
                }
            }
            if (error !== null) {
                throw error;
            } else {
                return retval;
            }
        };
    };
    ns.combinedCancel = combinedCancel;


    /**
     * An insertion happened on the sequence.
     *
     * @class
     * @property rIdx {number} Negative index at which the element was
     *      inserted. For example, 0 means it was appended to the sequence,
     *      after all other elements.
     * @property elem {} The element that was inserted.
     * @memberOf module:mpenc/helper/async
     */
    var SequenceInsert = struct.createTupleClass("rIdx", "elem");
    ns.SequenceInsert = SequenceInsert;

    /**
     * A sequence that allows subscription to its updates.
     *
     * @class
     * @extends Array
     * @memberOf module:mpenc/helper/async
     */
    var ObservableSequence = function() {
        this._updates = new Observable();
    };

    ObservableSequence.prototype = Object.create(Array.prototype);

    /**
     * Used by subclasses to publish an insert.
     *
     * @protected
     * @param rIdx {number}
     * @param elem {}
     * @see module:mpenc/helper/async.SequenceInsert
     */
    ObservableSequence.prototype.__rInsert__ = function(rIdx, item) {
        this._updates.publish(new SequenceInsert(rIdx, item));
    };

    /**
     * Subscribe to updates to the sequence.
     *
     * @param subscriber {module:mpenc/helper/async~subscriber}
     * @returns canceller {module:mpenc/helper/async~canceller}
     */
    ObservableSequence.prototype.onUpdate = function(subscriber) {
        return this._updates.subscribe(subscriber);
    };

    Object.freeze(ObservableSequence.prototype);
    ns.ObservableSequence = ObservableSequence;


    /**
     * A set that clients can watch for events on.
     *
     * <p>Provide Promises that resolve after a given diff occurs, even if it
     * is spread out over multiple distinct events, or if it occurs as part of
     * a strictly-larger diff.</p>
     *
     * <p>Useful for tracking e.g. memberships of a session or channel.</p>
     *
     * @class
     * @param init {module:mpenc/helper/struct.ImmutableSet} Initial value
     * @memberOf module:mpenc/helper/async
     */
    var PromisingSet = function(init) {
        if (!(this instanceof PromisingSet)) {
            return new PromisingSet(init);
        }

        this._value = ImmutableSet.from(init);
        this._expect = []; // { type, resolve, reject, <extra args> }
    };

    /**
     * @method
     * @returns {?module:mpenc/helper/struct.ImmutableSet} Current value
     */
    PromisingSet.prototype.value = function() {
        return this._value;
    };

    /**
     * If any member in <code>include</code> is included but later excluded
     * before the Promise fulfills, we reject it instead; and vice-versa for
     * <code>exclude</code>.
     *
     * TODO(xl): add "timeout" auto-reject functionality, using Promise.race
     *
     * @param diff {module:mpenc/helper/struct.ImmutableSet[]} 2-tuple of what
     *      to (<code>include</code>, <code>exclude</code>).
     * @returns {Promise} A promise that resolves when the given diff has taken
     *      place on the set.
     */
    PromisingSet.prototype.awaitDiff = function(diff) {
        var include = ImmutableSet.from(diff[0]);
        var exclude = ImmutableSet.from(diff[1]);
        _assert(!include.intersect(this._value).size);
        _assert(!exclude.subtract(this._value).size);

        var promise = ns.newPromiseAndWriters();
        this._expect.push({
            type: "diff",
            resolve: promise.resolve,
            reject: promise.reject,
            include: include,
            exclude: exclude,
            to_include: include,
            to_exclude: exclude,
        });
        return promise.promise;
    };

    PromisingSet.prototype._checkExpectation = function(entry, include, exclude) {
        switch (entry.type) {
        case "diff":
            if (entry.include.intersect(exclude).size) {
                throw new Error("OperationAborted: excluded wait-to-include members: " +
                    entry.include.intersect(exclude).toArray());
            }
            if (entry.exclude.intersect(include).size) {
                throw new Error("OperationAborted: included wait-to-exclude members: " +
                    entry.exclude.intersect(include).toArray());
            }
            entry.to_include = entry.to_include.subtract(include);
            entry.to_exclude = entry.to_exclude.subtract(exclude);
            return (!entry.to_include.size && !entry.to_exclude.size);
        default:
            throw new Error("unexpected expectation");
        }
        return false;
    };

    /**
     * Note that a given change has occured on the set.
     */
    PromisingSet.prototype.patch = function(diff) {
        var include = ImmutableSet.from(diff[0]);
        var exclude = ImmutableSet.from(diff[1]);
        _assert(!include.intersect(this._value).size);
        _assert(!exclude.subtract(this._value).size);

        this._value = this._value.patch([include, exclude]);
        var self = this;
        this._expect = this._expect.filter(function(entry) {
            try {
                var matched = self._checkExpectation(entry, include, exclude);
                if (matched) {
                    entry.resolve(self._value);
                }
                return !matched;
            } catch (e) {
                entry.reject(e);
                return false;
            }
        });
    };

    ns.PromisingSet = PromisingSet;


    // jshint -W055

    var _AutoNode = function(mkchild, cleanup) {
        if (!(this instanceof _AutoNode)) {
            return new _AutoNode(mkchild, cleanup);
        }
        this._mkchild = mkchild;
        this._cleanup = cleanup || function(){};
        this._child = new Map();
    };

    _AutoNode.prototype.size = function() {
        var i = 0;
        this._child.forEach(function(v, k) {
            i += v.size();
        });
        return i;
    };

    _AutoNode.prototype.has = function(k) {
        return this._child.has(k);
    };

    _AutoNode.prototype.get = function(k) {
        if (!this.has(k)) {
            var o = this._mkchild(this._cleanChild.bind(this, k));
            this._child.set(k, o);
        }
        return this._child.get(k);
    };

    _AutoNode.prototype._maybeClean = function() {
        if (!this.size()) {
            this._cleanup(this);
        }
    };

    _AutoNode.prototype._cleanChild = function(key, subj) {
        _assert(this._child.has(key));
        _assert(this._child.get(key) === subj);
        logger.debug("AutoNode deleting key: " + key);
        this._child.delete(key);
        this._maybeClean();
    };

    _AutoNode.prototype.getDescendant = function(path) {
        if (path === undefined ) {
            path = [];
        } else if (!(path instanceof Array)) {
            throw new Error("getDescendant needs an array, but given: " + path);
        }
        var node = this;
        for (var i=0; i<path.length; i++) {
            node = node.get(path[i]);
        }
        return node;
    };

    _AutoNode.prototype.activeChildren = function() {
        var active = [];
        this._child.forEach(function(v, k) {
            if (v.size()) {
                active.push(k);
            }
        });
        return active;
    };

    var _ObservableNode = function(cleanup) {
        if (!(this instanceof _ObservableNode)) {
            return new _ObservableNode(cleanup);
        }
        _AutoNode.call(this, function(c) { return new _ObservableNode(c); }, cleanup);
        this._capture = new Observable();
        this._bubble = new Observable();
        this._publishing = false;
    };
    _ObservableNode.prototype = Object.create(_AutoNode.prototype);

    _ObservableNode.prototype.size = function() {
        return this._capture.size() + this._bubble.size() + _AutoNode.prototype.size.call(this);
    };

    _ObservableNode.prototype._maybeClean = function() {
        if (!this._publishing) {
            _AutoNode.prototype._maybeClean.call(this);
        }
    };

    _ObservableNode.prototype.subscribe = function(sub, useCapture) {
        var obs = (useCapture)? this._capture: this._bubble;
        var cancel = obs.subscribe(sub);
        var self = this;
        return function() {
            return cancel()? (!!self._maybeClean() || true): false;
        };
    };

    _ObservableNode.prototype.pubDeep = function(evt, i) {
        if (!i) { i = 0; }
        this._publishing = true;
        this._capture.publish(evt);
        if (i < evt.length && this._child.has(evt[i])) {
            this.get(evt[i]).pubDeep(evt, i+1);
        }
        this._bubble.publish(evt);
        this._publishing = false;
        this._maybeClean();
    };

    Object.freeze(_ObservableNode.prototype);

    /**
     * Context for publishing and subscribing to events.
     *
     * @class
     * @param evtcls {Array} Possible event types published by this context.
     *      It should be an array of classes that represent Array-like objects,
     *      with a length and numerical indexes. See also {@link
     *      module:mpenc/helper/struct.createTupleClass} for compatible types.
     * @memberOf module:mpenc/helper/async
     */
    var EventContext = function(evtcls) {
        if (!(this instanceof EventContext)) {
            return new EventContext(evtcls);
        }
        _AutoNode.call(this, function(c) { return new _ObservableNode(); });
        evtcls = new ImmutableSet(evtcls);
        var non_evtcls = evtcls.toArray().filter(function(ec) {
            return (typeof ec.prototype.length !== "number");
        });
        if (non_evtcls.length) {
            throw new Error("not a valid event class: " + non_evtcls);
        }
        this._evtcls = evtcls;
    };

    EventContext.maybeInject = function(evtctx, evtcls) {
        if (!evtctx) {
            return new EventContext(evtcls);
        } else if (new ImmutableSet(evtcls).subtract(evtctx.evtcls()).size() === 0) {
            return evtctx;
        } else {
            throw new Error("inject evt does not support " + evtcls);
        }
    };

    EventContext.prototype = Object.create(_AutoNode.prototype);

    /**
     * Get all event classes that this context supports.
     */
    EventContext.prototype.evtcls = function() {
        return this._evtcls;
    };

    EventContext.prototype.get = function(evtcls) {
        if (!this._evtcls.has(evtcls)) {
            throw new Error("not an expected event class: " + evtcls + " not in " + this._evtcls);
        }
        return _AutoNode.prototype.get.call(this, evtcls);
    };

    /**
     * Returns a Subscribe function to add subscribers to matching events.
     *
     * @param evtcls {function} Matching event type.
     * @param prefix {Array} Matching event prefix.
     * @param useCapture {boolean} Whether to fire the subscription before
     *      ones with longer matching prefixes. Default: false, fire after.
     * @returns {module:mpenc/helper/async~subscriber}
     */
    EventContext.prototype.subscribe = function(evtcls, prefix, useCapture) {
        useCapture = !!useCapture;
        var subs = this.get(evtcls).getDescendant(prefix);
        return Subscribe.wrap(function(sub) { return subs.subscribe(sub, useCapture); });
    };

    /**
     * Publish an event, firing all subscriptions.
     *
     * @param evt {object} Event to publish
     */
    EventContext.prototype.publish = function(evt) {
        var evtcls = evt.constructor;
        this.get(evtcls).pubDeep(evt);
    };

    EventContext.prototype.activeChildren = function(evtcls, prefix) {
        var subs = this.get(evtcls).getDescendant(prefix);
        return subs.activeChildren();
    };

    /**
     * Subscribe to and republish events from another EventContext.
     */
    EventContext.prototype.chainFrom = function(evtctx, evtcls) {
        var self = this;
        return combinedCancel(new ImmutableSet(evtcls).toArray().map(function(ec) {
            evtctx.subscribe(ec)(self.publish.bind(self));
        }));
    };

    Object.freeze(EventContext.prototype);
    ns.EventContext = EventContext;

    // jshint +W055


    /**
     * A source of events.
     *
     * @interface
     * @property EventTypes {module:mpenc/helper/struct.ImmutableSet} Event types emitted by this source.
     * @memberOf module:mpenc/helper/async
     */
    var EventSource = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * Subscribe to events; delegates to some underlying internal EventContext.
     *
     * @method
     * @param evtcls {function} Matching event type.
     * @param prefix {Array} Matching event prefix.
     * @param useCapture {boolean} Whether to fire the subscription before
     *      ones with longer matching prefixes. Default: false, fire after.
     * @returns {module:mpenc/helper/async~subscriber}
     * @see module:mpenc/helper/async.EventContext#subscribe
     */
    EventSource.prototype.onEvent;

    Object.freeze(EventSource.prototype);
    ns.EventSource = EventSource;
    // jshint +W030


    /**
     * Timer that executes callbacks in the order they were subscribed.
     *
     * (Browsers don't typically make this ordering guarantee.)
     *
     * Note: when created, this creates a background task to run the scheduled
     * callbacks via <code>setInterval</code>, which uses up resources. It
     * should generally not be necessary to create more than one instance.
     *
     * @class
     * @param tps {number} Ticks per second. Default: 1000
     * @memberOf module:mpenc/helper/async
     */
    var Timer = function(tps) {
        this._tpms = (tps) ? tps/1000 : 1;
        this._cb = {};
        this._lastCompleted = this._realNow();

        var tId = setInterval(this._runTick.bind(this), 0.5 / this._tpms);

        this.stop = function() {
            clearInterval(tId);
            var s = 0;
            for (var k in this._cb) {
                s += this._cb[k].size();
            }
            return s;
        };
        var self = this;
    };

    if (typeof performance === "undefined") {
        Timer.prototype._realNow = function() {
            return Math.floor(new Date().getTime() * this._tpms);
        };
    } else {
        Timer.prototype._realNow = function() {
            return Math.floor(performance.now() * this._tpms);
        };
    }

    /**
     * Get the current tick. This has no semantics outside of this object.
     *
     * @returns tick {number}
     */
    Timer.prototype.now = function() {
        return this._lastCompleted + 1;
    };

    /**
     * Schedule future timed calls.
     *
     * <p>If <code>action</code> is omitted, this instead returns a {@link
     * module:mpenc/helper/async.Subscribe} that runs subscriptions after
     * the given number of ticks. One pattern is to use this as an input to
     * {@link module:mpenc/helper/async.Subscribe#withBackup}:</p>
     *
     * <pre>
     * myObservable.subscribe
     *      .withBackup(timer.after(myInterval), timeoutCb)(successCb)
     * </pre>
     *
     * @param ticks {number} Number of ticks in the future to schedule the
     *      action for. How long this is in real terms is defined by the timer.
     * @param action {?function} 1-arg function to run, takes the current tick.
     * @returns canceller {module:mpenc/helper/async~canceller}
     */
    Timer.prototype.after = function(ticks, action) {
        if (ticks < 0) {
            throw new Error("can't schedule in the past");
        }
        if (!action) {
            return Subscribe.wrap(this.after.bind(this, ticks));
        }
        var t = this.now() + Math.floor(ticks);
        if (!(t in this._cb)) {
            this._cb[t] = new Observable(false, SubscriptionReentry.ADD_REM);
        }
        var self = this;
        var obs = this._cb[t];
        var cancel = obs.subscribe(action);
        return function() {
            if (!cancel() || obs !== self._cb[t]) {
                // already cancelled or already run
                return false;
            }
            if (!obs.size() && t !== self.now()) {
                // nothing left and not currently being iterated through
                delete self._cb[t];
            }
            return true;
        };
    };

    Timer.prototype._runTick = function() {
        var realNow = this._realNow();
        var lastCompleted = this._lastCompleted;
        if (realNow <= lastCompleted) {
            return;
        }
        for (var t=lastCompleted+1; t<realNow; t++) {
            var obs = this._cb[t];
            if (obs) {
                obs.publish(t);
                if (t in this._cb) {
                    delete this._cb[t];
                }
            }
            //logger.debug("lastCompleted: " + t + " @ " + this._realNow());
            this._lastCompleted = t;
        }
    };

    /**
     * Stop the timer.
     *
     * <p>Applications should generally not need to call this.</p>
     *
     * @method
     * @returns remaining {number} Number of subscriptions yet to fire, that
     *      will now never be fired.
     */
    Timer.prototype.stop;

    Object.freeze(Timer.prototype);
    ns.Timer = Timer;


    /**
     * Repeatedly schedule calls to an action until stopped.
     *
     * @class
     * @param timer {module:mpenc/helper/async.Timer} To execute the calls.
     * @param intervals {(number|Iterable|Iterator)} An iterable of int, that
     *      represents the ticks between calls. Alternatively, a single int,
     *      interpreted as a non-terminating constant sequence. If the iterable
     *      runs out of elements, the calls stop.
     * @param action {function} 0-arg function to run. Return true to tell the
     *      monitor to stop, e.g. if the task it represents "finishes". If the
     *      action throws an exception, the monitor also stops.
     * @param name {string=} Optional name for the monitor, for logging.
     * @memberOf module:mpenc/helper/async
     */
    var Monitor = function(timer, intervals, action, name) {
        if (!(this instanceof Monitor)) {
            return new Monitor(timer, intervals, action, name);
        }

        this._timer = timer;
        this._action = action;
        this._name = name;

        this._intervals = null;
        this._cancel = null;
        this._stopped = true;

        this.reset(intervals);
    };

    Monitor.prototype._next = function() {
        var next = this._intervals.next();
        if (next.done) {
            this.stop();
            return;
        }
        logger.debug("monitor " + this._name + " timed in " + next.value + " ticks");
        this._cancel = this._timer.after(next.value, this._run.bind(this));
    };

    Monitor.prototype._run = function() {
        if (this._stopped) {
            throw new Error("monitor " + this._name + " attempted to run even though stopped, faulty timer?");
        }
        var stop = true;
        try {
            stop = !!this._action();
        } catch(e) {
            __SubscriberFailure_publishGlobal(this._action, undefined, e);
        } finally {
            if (stop) {
                this.stop();
            } else if (!this._stopped) { // e.g. if _action() called stop()
                this._next();
            }
        }
    };

    Monitor.prototype.state = function() {
        if (this._stopped) {
            _assert(!this._cancel);
            _assert(!this._intervals);
            return "STOPPED";
        } else if (this._cancel) {
            _assert(this._intervals);
            return "RUNNING";
        } else {
            _assert(this._intervals);
            return "PAUSED";
        }
    };

    /**
     * Pause the monitor.
     *
     * The currently-scheduled action is cancelled.
     */
    Monitor.prototype.pause = function() {
        if (this.state() !== "RUNNING") {
            throw new Error("can only pause running monitor");
        }
        this._cancel();
        this._cancel = null;
    };

    /**
     * Resume the monitor.
     *
     * The action is scheduled with the next interval in the sequence.
     */
    Monitor.prototype.resume = function() {
        if (this.state() !== "PAUSED") {
            throw new Error("can only resume paused monitor");
        }
        this._next();
    };

    /**
     * Reset the interval sequence.
     *
     * The currently-scheduled action is cancelled, and re-scheduled with
     * a *new* sequence.
     *
     * @param intervals {(number|Iterable|Iterator)} see constructor
     */
    Monitor.prototype.reset = function(intervals) {
        if (this._cancel) {
            this.pause();
        }
        if (typeof intervals === "number") {
            var k = intervals;
            intervals = { next: function() { return { done: false, value: k }; } };
        }
        this._intervals = struct.toIterator(intervals);
        this._stopped = false;
        this.resume();
        _assert(this.state() === "RUNNING" || this.state() === "STOPPED");
    };

    /**
     * Stop the monitor.
     *
     * No more actions will be scheduled, until a reset.
     */
    Monitor.prototype.stop = function() {
        if (this._cancel) {
            this.pause();
        }
        this._intervals = null;
        this._stopped = true;
        _assert(this.state() === "STOPPED");
    };

    Object.freeze(Monitor.prototype);
    ns.Monitor = Monitor;

    return ns;
});
