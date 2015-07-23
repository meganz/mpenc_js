/*
 * Created: 03 Jul 2015 Ximin Luo <xl@mega.co.nz>
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
    "mpenc/helper/struct",
], function(struct) {
    "use strict";

    /**
     * @exports mpenc/channel
     * @description
     * Group transport channel abstractions.
     */
    var ns = {};

    var ImmutableSet = struct.ImmutableSet;

    // The following are JSDoc typedefs
    // They may be referred to as {module:mpenc/channel~$name}

    /**
     * Something happened on the group transport channel.
     *
     * @typedef {(module:mpenc/helper/utils~RawRecv|module:mpenc/channel~ChannelControl)} ChannelNotice
     */

    /**
     * Try to do something to/on the group transport channel.
     *
     * For RawRecv, it is not guaranteed that the message will reach the
     * intended set of recipients. For example, someone may leave the channel
     * before the server receives your message. The actual set of recipients
     * is determined by the server, but will be known by the client when the
     * server echoes it back in a ChannelNotice event.
     *
     * @typedef {(module:mpenc/helper/utils~RawSend|module:mpenc/channel~ChannelControl)} ChannelAction
     */

    /**
     * A channel control message.
     *
     * <p>In the context of a <code>ChannelNotice</code>, this means the event
     * has already happened. In the context of a <code>ChannelAction</code>,
     * this means we're trying to make the event happen. Valid values are:</p>
     *
     * <dl>
     * <dt><code>{ enter: true }</code></dt><dd>We enter the channel.</dd>
     * <dt><code>{ leave: true }</code></dt><dd>We leave the channel.</dd>
     * <dt><code>{ enter: *, leave: * }</code></dt><dd>Others enter/leave the
     * channel. The values must be "ImmutableSet"-like values, i.e. such that
     * {@link module:mpenc/helper/struct.ImmutableSet.from ImmutableSet.from}
     * does not throw an error.</dd>
     * </dl>
     *
     * <p>One may use {@link module:mpenc/channel.checkChannelControl
     * checkChannelControl} to check valid values.</p>
     *
     * @typedef {Object} ChannelControl
     * @property [enter] {(boolean|module:mpenc/helper/struct.ImmutableSet)}
     *      Members to enter the channel. If <code>true</code>, we ourselves
     *      are the object of the event, and leave must be omitted.
     * @property [leave] {(boolean|module:mpenc/helper/struct.ImmutableSet)}
     *      Members to leave the channel. If <code>true</code>, we'ourselves
     *      are the object of the event, and enter must be omitted.
     */

    /**
     * @param act {module:mpenc/channel~ChannelControl} Action to check.
     * @return {module:mpenc/channel~ChannelControl} Validated action, maybe
     *      with canonicalised values.
     * @throws If the action was not valid and could not be canonicalised.
     */
    ns.checkChannelControl = function(act) {
        if (act.enter === true) {
            if (act.leave !== undefined) {
                throw new Error("tried to create ChannelControl [enter] with non-empty leave");
            }
        } else if (act.leave === true) {
            if (act.enter !== undefined) {
                throw new Error("tried to create ChannelControl [leave] with non-empty enter");
            }
        } else {
            var enter = ImmutableSet.from(act.enter);
            var leave = ImmutableSet.from(act.leave);
            if (!enter.size && !leave.size) {
                throw new Error("tried to create ChannelControl with empty membership change");
            }
            if (!struct.isDisjoint(enter, leave)) {
                throw new Error("tried to create ChannelControl with contradictory membership change");
            }
            return { enter: enter, leave: leave };
        }
        return act;
    };


    /**
     * A group transport channel.
     *
     * <p>Represents a group that has an existence outside of its membership. That
     * is, unlike {@link module:mpenc/session.Session}, "not in the channel" and
     * "the channel has one member, i.e. us" are distinct states. We expect that
     * the group protocol does not allow non-members to query the membership of the
     * channel, nor receive updates about the membership. In code terms:</p>
     *
     * <ul>
     * <li><code>curMembers()</code><ul>
     *   <li>returns <code>null</code> for "not in the channel"</li>
     *   <li>returns <code>ImmutableSet([owner])</code> for "the channel has one member"</li>
     *   <li>never returns an empty <code>ImmutableSet</code>.</li>
     * </ul></li>
     * <li>The first event received (i.e. published to subscribers of
     * <code>onRecv</code>) must be a <code>{ enter: true }</code>.</li>
     * <li>The event immediately after a <code>{ leave: true }</code> event, if
     * any, must be a <code>{ enter: true }</code>.</li>
     * </ul>
     *
     * <p>We expect that everyone receives the same events in the same order.
     * This is checked by {@link module:mpenc/impl/channel.ServerOrder}. Other
     * than this, implementations are free to choose how to order, e.g.
     * messages sent concurrently at the same time by different members. In
     * particular, there is no guarantee that an event <code>E</code> sent at
     * time <code>T</code> when the channel membership was <code>M</code>, will
     * be emitted back when the channel still has members <code>M</code>.</p>
     *
     * <p>The instantiated types for <code>ReceivingExecutor</code> are:</p>
     *
     * <ul>
     * <li><code>{@link module:mpenc/channel.GroupChannel#onRecv|RecvOutput}</code>:
     *      {@link module:mpenc/channel~ChannelNotice}</li>
     * <li><code>{@link module:mpenc/channel.GroupChannel#send|SendInput}</code>:
     *      {@link module:mpenc/channel~ChannelAction}</li>
     * </ul>
     *
     * <p>Implementations <em>need not</em> define <code>execute()</code> when
     * the input is a {@link module:mpenc/helper/utils~RawSend}, but they
     * <strong>must</strong> define it when the input is a {@link
     * module:mpenc/channel~ChannelControl}.</p>
     *
     * <p>See {@link module:mpenc/impl/dummy.DummyGroupChannel} for an example.</p>
     *
     * @interface
     * @augments module:mpenc/helper/utils.ReceivingExecutor
     * @memberOf module:mpenc/channel
     */
    var GroupChannel = function() {
        throw new Error("cannot instantiate an interface");
    };
    // jshint -W030

    /**
     * @method
     * @returns {?module:mpenc/helper/struct.ImmutableSet} The current channel
     *      membership. If <code>null</code>, it means we are not currently in
     *      the channel.
     */
    GroupChannel.prototype.curMembers;

    ns.GroupChannel = GroupChannel;
    // jshint +W030


    return ns;
});
