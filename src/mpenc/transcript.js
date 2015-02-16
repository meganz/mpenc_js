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
     * Created: 28 Mar 2014-2015 Ximin Luo <xl@mega.co.nz>
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


    /**
     * A PartialOrder.
     *
     * TODO(xl): document
     *
     * @class
     * @memberOf module:mpenc/transcript
     */
    var PartialOrder = function() {
        /** @lends module:mpenc/transcript.PartialOrder.prototype */
        var self = Object.create(PartialOrder.prototype);

        /**
         * Number of elements.
         * @member {number}
         */
        self.length;

        /** All the ids as an array.
         * @method
         * @returns {Array} */
        self.all;

        /** The minimal ids.
         * @method
         * @returns {module:mpenc/helper/struct.MiniSet} */
        self.min;

        /** The maximal ids.
         * @method
         * @returns {module:mpenc/helper/struct.MiniSet} */
        self.max;

        /** The data for the given id.
         * @method
         * @param {string} id
         * @returns {*} The data, e.g. a message object.
         */
        self.msg;

        /** The direct predecessors of the given id.
         * @method
         * @param {string} id
         * @returns {module:mpenc/helper/struct.MiniSet} */
        self.pre;

        /** The direct successors of the given id.
         * @method
         * @param {string} id
         * @returns {module:mpenc/helper/struct.MiniSet} */
        self.suc;

        /** True if id1 &le; id2, i.e. id1 = pre<sup>n</sup>(id2) for some n &ge; 0.
         *
         * <p>This is a poset, so ¬(id1 &le; id2) does not imply (id2 &le; id1).</p>
         * @method
         * @param {string} id1
         * @param {string} id2
         * @returns {boolean}  */
        self.le;

        /** True if id1 &ge; id2, i.e. id1 = suc<sup>n</sup>(id2) for some n &ge; 0.
         *
         * <p>This is a poset, so ¬(id1 &ge; id2) does not imply (id2 &ge; id1).</p>
         * @method
         * @param {string} id1
         * @param {string} id2
         * @returns {boolean}  */
        self.ge;

        throw new Error("interface not implemented");
    };
    PartialOrder.prototype.__invariants = {
        PO_transitive: function(po) {
            // TODO
        },
        PO_acyclic: function(po) {
            // TODO
        },
    };


    /**
     * A Transcript.
     *
     * TODO(xl): document
     *
     * @class
     * @augments module:mpenc/transcript.PartialOrder
     * @memberOf module:mpenc/transcript
     */
    var Transcript = function() {
        /** @lends module:mpenc/transcript.Transcript.prototype */
        var self = Object.create(Transcript.prototype);

        /**
         * @method
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.allUId;

        /**
         * @method
         * @param {string} mId
         * @returns {string} uId */
        self.uId;

        /**
         * @method
         * @param {string} mId
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.ruId;

        /**
         * @method
         * @param {string} uId
         * @returns {string[]} List of mIds */
        self.by;

        /**
         * @method
         * @param {string} mId
         * @returns {Object.<string, number>} Map of uId -> mId. */
        self.context;

        /**
         * @method
         * @param {string} mId
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.unackby;

        /**
         * @method
         * @returns {module:mpenc/helper/struct.MiniSet} Set of mIds. */
        self.unacked;

        /**
         * @method
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.curUId;

        /**
         * @method
         * @param {string} mId
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.mem;

        /**
         * @method
         * @param {string[]} mIds
         * @returns {module:mpenc/helper/struct.MiniSet} Set of uIds. */
        self.mergeMem;

        // TODO(xl): document the following, they are used for
        // ratcheting and decoding

        self.prevS;

        self.prevR;

        self.nextS;

        self.nextR;

        throw new Error("interface not implemented");
    };
    Transcript.prototype = Object.create(PartialOrder.prototype);
    Transcript.prototype.__invariants = {
        TS_author_messages_total_order: function(ts) {
            // TODO
        },
        TS_freshness_consistent: function(ts) {
            // TODO
        },
    };


    ns.Transcript = Transcript;
    ns.PartialOrder = PartialOrder
    return ns;
});
