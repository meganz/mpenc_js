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
     * Things that can happen in the group transport channel.
     *
     * This is either a received packet, or a membership change notice.
     *
     * @typedef {(module:mpenc/helper/utils.RawRecv|module:mpenc/channel~ChannelControl)} ChannelNotice
     * @see module:mpenc/channel.GroupChannel#onRecv
     * @see module:mpenc/channel~ChannelAction
     */

    /**
     * Things that can be done to/on the group transport channel.
     *
     * This is either a to-be-sent packet, or a membership change request.
     *
     * It is not guaranteed that the message will reach the intended set of
     * recipients, or be placed directly after the currently-received sequence
     * of events. For example, someone may leave the channel before the
     * transport receives your message.
     *
     * The actual recipients and previous context, will be known by the client
     * when the transport echoes it back in a `ChannelNotice` event.
     *
     * @typedef {(module:mpenc/helper/utils.RawSend|module:mpenc/channel~ChannelControl)} ChannelAction
     * @see module:mpenc/channel.GroupChannel#send
     * @see module:mpenc/channel~ChannelNotice
     */

    /**
     * A channel control message.
     *
     * In the context of a `ChannelNotice`, this means the event has already
     * happened. In the context of a `ChannelAction`, this means we're trying
     * to make the event happen. Valid values are:
     *
     * <dl>
     * <dt>`{ enter: true }`</dt><dd>We enter the channel. If this
     * is a ChannelNotice, `members` is also defined.</dd>
     * <dt>`{ leave: true }`</dt><dd>We leave the channel.  If this
     * is a ChannelNotice, `members` is also defined.</dd>
     * <dt>`{ enter: *, leave: * }`</dt><dd>Others enter/leave the
     * channel. The values must be "ImmutableSet"-like values, i.e. such that
     * {@link module:mpenc/helper/struct.ImmutableSet.from ImmutableSet.from}
     * does not throw an error.</dd>
     * </dl>
     *
     * One may use {@link module:mpenc/channel.checkChannelControl
     * checkChannelControl} to check valid values.
     *
     * @typedef {Object} ChannelControl
     * @property [enter] {(boolean|module:mpenc/helper/struct.ImmutableSet)}
     *      Members to enter the channel. If `true`, we ourselves
     *      are the object of the event, and leave must be omitted.
     * @property [leave] {(boolean|module:mpenc/helper/struct.ImmutableSet)}
     *      Members to leave the channel. If `true`, we'ourselves
     *      are the object of the event, and enter must be omitted.
     * @property [members] {(boolean|module:mpenc/helper/struct.ImmutableSet)}
     *      In a ChannelNotice, where `enter: true` or `leave:
     *      true`, this represents the members in the channel after we
     *      enter or before we leave, respectively.
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
     * A group transport channel API, for a higher-layer client component that
     * wishes to participate in it. Common transport client libraries should be
     * adapted to *provide this interface*, when used with our system.
     *
     * Implementors may use {@link module:mpenc/impl/channel.BaseGroupChannel}
     * as a base to extend. However, you should read this documentation first,
     * on how this is supposed to behave:
     *
     * The channel exists separately from its members' participation in it.
     * That is, unlike {@link module:mpenc/session.Session}, "we are not part
     * of the channel" and "we are the only member" are distinct states.
     *
     * Whilst part of the channel, the client receives a sequence of {@link
     * module:mpenc/channel~ChannelNotice} events from the channel. We expect
     * that the channel emits events to all members reliably in the same order.
     * To give a simple example that ignores membership changes: if we receive
     * the sequence `[a, b, c]`, we can expect that others have received `[]`,
     * `[a]`, `[a, b]`, or `[a, b, c]` and will probably eventually receive
     * `[a, b, c]`, but they will never receive e.g. `[a, c, b]` or `[a, c]` or
     * `[a, d, b, c]`. However, this component need not verify or enforce this
     * property, beyond correctly implementing the transport protocol; that is
     * handled by other external components in a generic way.
     *
     * Whilst part of the channel, the client can attempt to issue {@link
     * module:mpenc/channel~ChannelAction} requests. These may be satisfied up
     * to once, possibly after other events are received - i.e. the channel
     * does not preserve the context of the request. For example, there is no
     * guarantee that a request `R_i` sent when the channel membership was `M`,
     * will be received back (as event `E_i`) when the membership is still `M`.
     *
     * We do not expect that the group protocol allows non-members to query the
     * membership of the channel, nor receive updates about the membership.
     * That is, we makes no attempt to use or provide such a capability, but it
     * does not matter if the protocol actually provides it.
     *
     * In concrete code terms:
     *
     * - `curMembers()`
     *   - returns `null` for "not in the channel"
     *   - returns `ImmutableSet([owner])` for "the channel has one member"
     *   - never returns an `ImmutableSet` that does not contain `owner`
     * - The first event received (i.e. published to subscribers of `onRecv`)
     *   must be a `{ enter: true }`.
     * - The event immediately after a `{ leave: true }` event, if any, must be
     *   a `{ enter: true }`.
     *
     * The instantiated types for `ReceivingExecutor` are:
     *
     * - `{@link module:mpenc/channel.GroupChannel#onRecv|RecvOutput}`:
     *   {@link module:mpenc/channel~ChannelNotice}
     * - `{@link module:mpenc/channel.GroupChannel#send|SendInput}`:
     *   {@link module:mpenc/channel~ChannelAction}
     *
     * Implementations *need not* define `execute()` when the input is a
     * {@link module:mpenc/helper/utils.RawSend}, but they **must** define it
     * when the input is a {@link module:mpenc/channel~ChannelControl}.
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
     *      membership. If `null`, it means we are not currently in the
     *      channel. This must be consistent with the sequence of events that
     *      we already observed.
     */
    GroupChannel.prototype.curMembers;

    ns.GroupChannel = GroupChannel;
    // jshint +W030


    return ns;
});
