/**
 * @fileOverview
 * Test of the `mpenc/handler` module.
 */

/*
 * Created: 27 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

define([
    "mpenc/session",
    "mpenc/helper/utils",
    "megalogger",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
    "sinon/stub",
], function(ns, utils, MegaLogger,
            chai, sinon_assert, sinon_sandbox, sinon_spy, stub) {
    "use strict";

    var assert = chai.assert;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
        sandbox.stub(MegaLogger._logRegistry.session, '_log');
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("SessionTracker class", function() {
        describe('constructor', function() {
            it('just make an instance', function() {
                var maxSizeFunc = stub();
                var tracker = new ns.SessionTracker('James', maxSizeFunc);
                assert.strictEqual(tracker.name, 'James');
                assert.deepEqual(tracker.sessions, {});
                assert.deepEqual(tracker.sessionIDs, []);
                assert.deepEqual(tracker.pubKeyMap, {});
                assert.strictEqual(tracker.drop, true);
            });
        });

        describe('#addSession method', function() {
            it('add a first session', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub();
                var tracker = new ns.SessionTracker('Three Stooges', maxSizeFunc);
                tracker.addSession('film debut', members, pubKeys, 'Soup to Nuts');
                assert.deepEqual(tracker.sessionIDs, ['film debut']);
                assert.deepEqual(tracker.sessions,
                                 {'film debut': {
                                     members: members,
                                     groupKeys: ['Soup to Nuts'] }});
                assert.deepEqual(tracker.pubKeyMap, pubKeysDir);
                assert.strictEqual(maxSizeFunc.callCount, 1);
            });

            it('add an existing session', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Vincent', 'Gregory'];
                var pubKeys = ['Crabbe', 'Goyle'];
                var pubKeysDir = {'Vincent': 'Crabbe', 'Gregory': 'Goyle'};
                var groupKey = 'foo';
                var errorMessage = 'Attept to add a session with an already existing ID on classic combos.';
                assert.throws(function() { tracker.addSession(_td.SESSION_ID, members, pubKeys, groupKey); },
                              errorMessage);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });

            it('add a session, buffer exceeds, dropping one', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub().returns(1);
                var tracker = new ns.SessionTracker('Three Stooges', maxSizeFunc);
                tracker.sessionIDs = ['film debut'];
                tracker.sessions = {'film debut': {
                                         members: members,
                                         groupKeys: ['Soup to Nuts'] }};
                tracker.pubKeyMap = pubKeysDir;
                tracker.addSession('second film', members, pubKeys, 'Nertsery Rhymes');
                assert.deepEqual(tracker.sessionIDs, ['second film']);
                assert.deepEqual(tracker.sessions,
                                 {'second film': {
                                     members: members,
                                     groupKeys: ['Nertsery Rhymes'] }});
                assert.deepEqual(tracker.pubKeyMap, pubKeysDir);
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [30, ['Three Stooges DROPPED session film debut at size 1, potential data loss.']]);
            });

            it('add a session, buffer exceeds, no drop', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub().returns(1);
                var tracker = new ns.SessionTracker('Three Stooges', maxSizeFunc, false);
                tracker.sessionIDs = ['film debut'];
                tracker.sessions = {'film debut': {
                                         members: members,
                                         groupKeys: ['Soup to Nuts'] }};
                tracker.pubKeyMap = pubKeysDir;
                tracker.addSession('second film', members, pubKeys, 'Nertsery Rhymes');
                assert.lengthOf(tracker.sessionIDs, 2);
                assert.lengthOf(Object.keys(tracker.sessions), 2);
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [20, ['Three Stooges is 1 items over expected capacity.']]);
            });
        });

        describe('#addGroupKey method', function() {
            it('add a group key to a session', function() {
                var members = ['The Doctor', 'Rose Tyler'];
                var maxSizeFunc = stub();
                var tracker = new ns.SessionTracker('Doctor Who', maxSizeFunc);
                tracker.sessions = {'Series 1': {
                                       members: members,
                                       groupKeys: ['Chris Eccleston'] }};
                tracker.sessionIDs = ['Series 1'];
                tracker.addGroupKey('Series 1', 'David Tennant');
                assert.deepEqual(tracker.sessions,
                                 {'Series 1': {
                                     members: members,
                                     groupKeys: ['David Tennant', 'Chris Eccleston'] }});
            });

            it('duplicate group key for existing session', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Moe', 'Larry', 'Curly'];
                var groupKey = _td.GROUP_KEY;
                tracker.addGroupKey(_td.SESSION_ID, groupKey);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [20, ['classic combos ignores adding a group key already tracked.']]);
            });

            it('new group key for non-latest session', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessionIDs.unshift('TARDIS');
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                tracker.sessions['TARDIS'] = {
                    members: ['The Doctor', 'Rose Tyler'],
                    groupKeys: ['Gallifrey']
                };
                tracker.addGroupKey(_td.SESSION_ID, 'foo');
                assert.lengthOf(tracker.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(tracker.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [30, ['New group key added to non-current session on classic combos.']]);
            });
        });

        describe('#addGroupKeyLastSession method', function() {
            it('add a group key to a session', function() {
                var members = ['The Doctor', 'Rose Tyler'];
                var maxSizeFunc = stub();
                var tracker = new ns.SessionTracker('Doctor Who', maxSizeFunc);
                tracker.sessions = {'Series 1': {
                                       members: members,
                                       groupKeys: ['Chris Eccleston'] }};
                tracker.sessionIDs = ['Series 1'];
                tracker.addGroupKeyLastSession('David Tennant');
                assert.deepEqual(tracker.sessions,
                                 {'Series 1': {
                                     members: members,
                                     groupKeys: ['David Tennant', 'Chris Eccleston'] }});
            });
        });

        describe('#update method', function() {
            it('new session', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var groupKey = _td.GROUP_KEY;
                tracker.update(_td.SESSION_ID, members, pubKeys, groupKey);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
            });

            it('new group key only', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var groupKey = 'foo';
                tracker.update(_td.SESSION_ID, members, pubKeys, groupKey);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.lengthOf(tracker.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(tracker.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
            });

            it('mismatching participants', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Vincent', 'Gregory'];
                var pubKeys = ['Crabbe', 'Goyle'];
                var pubKeysDir = {'Vincent': 'Crabbe', 'Gregory': 'Goyle'};
                var groupKey = 'foo';
                var errorMessage = 'Attept to update classic combos with mis-matching members for a sesssion.';
                sandbox.stub(MegaLogger._logRegistry.assert, '_log');
                assert.throws(function() { tracker.update(_td.SESSION_ID, members, pubKeys, groupKey); },
                              errorMessage);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
                var log = MegaLogger._logRegistry.assert._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });
        });
    });
});
