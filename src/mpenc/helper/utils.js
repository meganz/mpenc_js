/*
 * Created: 7 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2016 by Mega Limited, Auckland, New Zealand
 *     https://mega.nz/
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
    "asmcrypto",
    "tweetnacl",
    "megalogger",
], function(asmCrypto, nacl, MegaLogger) {
    "use strict";

    /**
     * @exports mpenc/helper/utils
     * @private
     * @description
     * Some utilities.
     */
    var ns = {};

    var logger = MegaLogger.getLogger('utils', undefined, 'helper');

    ns._HEX_CHARS = '0123456789abcdef';

    // Some public interfaces
    // They may be referred to as {module:mpenc/helper/utils.$name}

    /**
     * Raw transport-layer data to be sent.
     *
     * @name RawSend
     * @interface
     * @property pubtxt {string} Raw data to send
     * @property recipients {module:mpenc/helper/struct.ImmutableSet}
     *      Transport-layer recipient addresses to send to.
     * @memberOf module:mpenc/helper/utils
     */

    /**
     * Raw transport-layer data that was received.
     *
     * @name RawRecv
     * @interface
     * @property pubtxt {string} Raw data that was received.
     * @property sender {string}
     *      Transport-layer unauthenticated sender address we received from.
     * @memberOf module:mpenc/helper/utils
     */

    // The following are JSDoc typedefs
    // They may be referred to as {module:mpenc/helper/utils~$name}

    /**
     * 1-arg function to get some "associates" of a subject.
     * @callback associates
     * @param subj {}
     * @returns {Array} list of associates
     */

    /**
     * 1-arg function to decide something about a subject.
     * @callback predicate
     * @param subj {}
     * @returns {boolean}
     */

    /**
     * Generates a new random 8-bit string. Each character in the string is
     * guaranteed to only have its lower 8 bits set.
     *
     * @param bytes {integer} Number of bytes to generate.
     * @returns {string} 8-bit string containing the entropy.
     * @private
     */
    ns.randomString = function(bytes) {
        var buffer = new Uint8Array(bytes);
        asmCrypto.getRandomValues(buffer);
        return ns.bytes2string(buffer);
    };


    /**
     * Convert a private ed25519 key seed to a public key. The private key seed
     * may be generated via `randomString(32)`.
     *
     * @returns {string} Public key as a 8-bit string.
     * @private
     */
    ns.toPublicKey = function(privKey) {
        return ns.bytes2string(nacl.sign.keyPair.fromSeed(ns.string2bytes(privKey)).publicKey);
    };


    /**
     * Convert a byte string to a Uint8Array.
     *
     * @param s {string} 8-bit string.
     * @returns {Uint8Array} Array of bytes.
     * @private
     */
    ns.string2bytes = function(s) {
        return new Uint8Array(s.split("").map(function(v) { return v.charCodeAt(0); }));
    };


    /**
     * Convert a Uint8Array to a byte string.
     *
     * @param a {Uint8Array} Array of bytes.
     * @returns {string} 8-bit string.
     * @private
     */
    ns.bytes2string = function(a) {
        return Array.prototype.map.call(a, function(v) { return String.fromCharCode(v); }).join("");
    };


    /**
     * Dumb array maker/initialiser helper.
     *
     * @param size {integer}
     *     Size of new array.
     * @param template
     *     Default value to initialise every element with.
     * @returns {array}
     *     The new array.
     */
    ns.arrayMaker = function(size, template) {
        var arr = new Array(size);
        for (var i = 0; i < size; i++) {
            arr[i] = template;
        }
        return arr;
    };


    /**
     * Checks for unique occurrence of all elements within the array.
     *
     * Note: Array members must be directly comparable for equality
     * (g. g. numbers or strings).
     *
     * @param theArray {integer}
     *     Array under scrutiny.
     * @returns {boolean}
     *     True for uniqueness.
     * @private
     */
    ns._arrayIsSet = function(theArray) {
        // Until ES6 is down everywhere to offer the Set() class, we need to work
        // around it.
        var mockSet = {};
        var item;
        for (var i = 0; i < theArray.length; i++) {
            item = theArray[i];
            if (item in mockSet) {
                return false;
            } else {
                mockSet[item] = true;
            }
        }
        return true;
    };


    /**
     * Checks whether one array's elements are a subset of another.
     *
     * Note: Array members must be directly comparable for equality
     * (g. g. numbers or strings).
     *
     * @param subset {array}
     *     Array to be checked for being a subset.
     * @param superset {array}
     *     Array to be checked for being a superset.
     * @returns {boolean}
     *     True for the first being a subset of the second.
     * @private
     */
    ns._arrayIsSubSet = function(subset, superset) {
        // Until ES6 is down everywhere to offer the Set() class, we need to work
        // around it.
        var mockSet = {};
        var item;
        for (var i = 0; i < superset.length; i++) {
            item = superset[i];
            if (item in mockSet) {
                return false;
            } else {
                mockSet[item] = true;
            }
        }
        for (var i = 0; i < subset.length; i++) {
            if (!(subset[i] in mockSet)) {
                return false;
            }
        }
        return true;
    };


    /**
     * Determines whether the list contains duplicates while excluding removed
     * elements (null).
     *
     * @param aList {array}
     *     The list to check for duplicates.
     * @returns {boolean}
     *     True for no duplicates in list.
     * @private
     */
    ns._noDuplicatesInList = function(aList) {
        var listCheck = [];
        for (var i = 0; i < aList.length; i++) {
            if (aList[i] !== null) {
                listCheck.push(aList[i]);
            }
        }
        return ns._arrayIsSet(listCheck);
    };


    /**
     * Returns a binary string representation of the SHA-256 hash function.
     *
     * @param data {string}
     *     Data to hash.
     * @returns {string}
     *     Binary string.
     */
    ns.sha256 = function(data) {
        return ns.bytes2string(asmCrypto.SHA256.bytes(data));
    };


    /**
     * (Deep) clones a JavaScript object.
     *
     * Note: May not work with some objects.
     *
     * See: http://stackoverflow.com/questions/728360/most-elegant-way-to-clone-a-javascript-object
     *
     * @param obj {object}
     *     The object to be cloned.
     * @returns {object}
     *     A deep copy of the original object.
     */
    ns.clone = function(obj, loose) {
        // Handle the 3 simple types, and null or undefined.
        if (null === obj || "object" !== typeof obj) {
            return obj;
        }

        // Handle date.
        if (obj instanceof Date) {
            var copy = new Date();
            copy.setTime(obj.getTime());
            return copy;
        }

        // Handle array.
        if (obj instanceof Array) {
            var copy = [];
            for (var i = 0, len = obj.length; i < len; i++) {
                copy[i] = ns.clone(obj[i]);
            }
            return copy;
        }

        // Handle array
        if (obj instanceof Uint8Array) {
            var copy = new Uint8Array(obj.length); // jshint ignore:line
            copy.set(obj);
            return copy;
        }

        // Handle object.
        if (obj instanceof Object && (obj.constructor === Object || loose)) {
            var copy = {};
            for (var attr in obj) {
                if (obj.hasOwnProperty(attr)) {
                    copy[attr] = ns.clone(obj[attr]);
                }
            }
            return copy;
        }

        throw new Error("Unable to copy obj! Its type isn't supported.");
    };


    /**
     * Constant time string comparison of two strings.
     *
     * @param str1 {string}
     *     The first string to be compared against the second.
     * @param str2 {string}
     *     The second string to be compared against the first.
     * @returns {boolean}
     *     A true on equality.
     */
    ns.constTimeStringCmp = function(str1, str2) {
        // Compare lengths - can save a lot of time.
        if (str1.length !== str2.length) {
            return false;
        }

        var diff = 0;
        for (var i = 0, l = str1.length; i < l; i++) {
            diff |= (str1[i] ^ str2[i]);
        }
        return !diff;
    };


    /**
     * (Deep) compares two JavaScript arrays.
     *
     * See: http://stackoverflow.com/questions/7837456/comparing-two-arrays-in-javascript
     *
     * @param arr1 {array}
     *     The first array to be compared against the second.
     * @param arr2 {array}
     *     The second array to be compared against the first.
     * @returns {boolean}
     *     A true on equality.
     */
    ns.arrayEqual = function(arr1, arr2) {
        // If the other array is a falsy value, return.
        if (!arr2) {
            return false;
        }

        // Compare lengths - can save a lot of time.
        if (arr1.length !== arr2.length) {
            return false;
        }

        for (var i = 0, l = arr1.length; i < l; i++) {
            // Check if we have nested arrays.
            if (arr1[i] instanceof Array && arr2[i] instanceof Array) {
                // Recurse into the nested arrays.
                if (!ns.arrayEqual(arr1[i], arr2[i])) {
                    return false;
                }
            } else if (arr1[i] !== arr2[i]) {
                // Warning - two different object instances will never be equal: {x:20} != {x:20}
                return false;
            }
        }
        return true;
    };


    /**
     * The state of the state machine was invalid.
     *
     * @class
     * @private
     * @param actual {*} Actual invalid state
     * @param label {string} Label to describe the error-checking
     * @param expected {Array} Expected valid states
     * @memberOf module:mpenc/helper/utils
     */
    var StateError = function(actual, label, expected) {
        this._actual    = actual;
        this._label     = label;
        this._expected  = expected;
    };

    StateError.prototype = Object.create(Error.prototype);

    /**
     * Generate a string message for this error.
     */
    StateError.prototype.toString = function() {
        return 'StateError: ' +  this._label + ' expected ' +  this._expected + ' actual: ' + this._actual;
    };

    Object.freeze(StateError.prototype);
    ns.StateError = StateError;


    /**
     * A finite state machine.
     *
     * @class
     * @private
     * @param changeType {function} State change factory, takes a (new, old)
     *      pair of states and returns an object.
     * @param initstate {*} Initial state of the state machine.
     * @memberOf module:mpenc/helper/utils
     */
    var StateMachine = function(changeType, initstate) {
        this._state = initstate;
        this.ChangeType = changeType;
    };

    /**
     * Get the current state.
     * @returns {SessionState}
     */
    StateMachine.prototype.state = function() {
        return this._state;
    };

    /**
     * Set a new state.
     * @param newState {SessionState} new state to set.
     * @returns {} Object describing the state transition; the caller should
     *      publish this in some {@link module:mpenc/helper/async.EventContext}.
     */
    StateMachine.prototype.setState = function(newState) {
        var oldState = this._state;
        this._state = newState;
        return new this.ChangeType(newState, oldState);
    };

    /**
     * Decorate a function with precondition and postcondition checks on the
     * state. Use something like:
     *
     * <pre>
     * MyStatefulClass.prototype.doSomething = StateMachine.transition(
     *     [valid pre states], [valid post states], function(params) {
     *     // function body. it should set the state somewhere
     * });
     * </pre>
     */
    StateMachine.transition = function(preStates, postStates, f) {
        return function() {
            try {
                var preState = this.state();
                logger.debug("pre state:" + preState);
                if (preStates.indexOf(preState) < 0) {
                    throw new StateError(preState, "precondition", preStates);
                }
                return f.apply(this, arguments);
            } finally {
                var postState = this.state();
                logger.debug("post state:" + postState);
                if (postStates.indexOf(postState) < 0) {
                    throw new StateError(postState, "postcondition", postStates);
                }
            }
        };
    };

    Object.freeze(StateMachine.prototype);
    ns.StateMachine = StateMachine;


    // jshint -W030

    /**
     * Accepts data-to-send, and notifies about data-received. This typically
     * represents a "less abstract" component than the client.
     *
     * <pre>
     *                             +-send()-+ <<<< +--------------+
     *                             |  this  |      | upper client |
     *                             +--------+ [>>] +-(subscribed receivers)
     * </pre>
     *
     * Implementations must define the following types:
     *
     * <ul>
     * <li>SendInput, expected input into send() from the upper layer</li>
     * <li>RecvOutput, result for subscribers of onRecv() to handle</li>
     * </ul>
     *
     * @interface
     * @memberOf module:mpenc/helper/utils
     */
    var ReceivingSender = function() {
        throw new Error("cannot instantiate an interface");
    };

    /**
     * Accept things to be sent by this component.
     *
     * @param input {SendInput} input to be handled for sending.
     * @returns {boolean} Whether the input was valid and was accepted.
     * @method
     */
    ReceivingSender.prototype.send;

    /**
     * Add a subscription for receive-items generated from this component.
     *
     * @method
     * @param subscriber {module:mpenc/helper/async~subscriber} 1-arg function
     *      that takes a <code>RecvOutput</code> object, and returns a boolean
     *      that represents whether it was valid for it and accepted by it.
     * @returns {module:mpenc/helper/async~canceller}
     */
    ReceivingSender.prototype.onRecv;

    ns.ReceivingSender = ReceivingSender;


    /**
     * @interface
     * @augments module:mpenc/helper/utils.ReceivingSender
     * @memberOf module:mpenc/helper/utils
     */
    var ReceivingExecutor = function() {
        throw new Error("cannot instantiate an interface");
    };

    ReceivingExecutor.prototype = Object.create(ReceivingSender.prototype);

    /**
     * Execute an action, initated by an initial SendInput.
     *
     * <p>The exact conditions on when the action finishes must be specified
     * on by the particular implementation, ideally on the class or interface
     * docstring. Unless otherwise specified, the fulfillment value for the
     * <code>Promise</code> returned by this method, is this object itself.</p>
     *
     * <p>This may not be defined for all inputs; the implementation should
     * specify exactly which ones. If this is defined for a given input,
     * <code>send()</code> for that input should behave exactly the same as
     * <code>return this.execute(input) !== null</code>; if not defined
     * then this should throw a "not implemented" error.</p>
     *
     * @method
     * @param input {SendInput} input to be handled for sending
     * @returns {?Promise} A Promise to allow the client to detect when the
     *      action finishes. <code>null</code> if the action was not started in
     *      the first place, e.g. if the input is invalid at the current time.
     */
    ReceivingExecutor.prototype.execute;

    ns.ReceivingExecutor = ReceivingExecutor;


    /**
     * Accepts data-received, and notifies about data-to-send. This typically
     * represents a "more abstract" component than the client.
     *
     * <pre>
     * (subscribed senders)-+ [<<] +--------+
     *       | lower client |      |  this  |
     *       +--------------+ >>>> +-recv()-+
     * </pre>
     *
     * Implementations must define the following types:
     *
     * <ul>
     * <li>RecvInput, expected input into recv() from the lower layer.</li>
     * <li>SendOutput, result for subscribers of onSend() to handle.</li>
     * </ul>
     *
     * @interface
     * @memberOf module:mpenc/helper/utils
     */
    var SendingReceiver = function() {
        throw new Error("cannot instantiate an interface");
    };

    /**
     * Accept things to be received by this component.
     *
     * @param input {RecvInput} input to be handled for receiving.
     * @returns {boolean} Whether the input was valid and was accepted.
     * @method
     */
    SendingReceiver.prototype.recv;

    /**
     * Add a subscription for send-items generated from this component.
     *
     * @method
     * @param subscriber {module:mpenc/helper/async~subscriber} 1-arg function
     *      that takes a <code>SendOutput</code> object, and returns a boolean
     *      that represents whether it was valid for it and accepted by it.
     * @returns {module:mpenc/helper/async~canceller}
     */
    SendingReceiver.prototype.onSend;

    ns.SendingReceiver = SendingReceiver;

    // jshint +W030


    return ns;
});
