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
                assert.strictEqual(tracker.drop, true);
            });
        });

        describe('#addSession method', function() {
            it('simply add a first session', function() {
                var members = ['Graham Chapman', 'John Cleese', 'Terry Gilliam',
                               'Eric Idle', 'Terry Jones', 'Michael Palin'];
                var maxSizeFunc = stub();
                var tracker = new ns.SessionTracker('Monty Python', maxSizeFunc);
                tracker.addSession('good skit', members, 'silly walk');
                assert.deepEqual(tracker.sessionIDs, ['good skit']);
                assert.deepEqual(tracker.sessions,
                                 {'good skit': {
                                     members: members,
                                     groupKeys: ['silly walk'] }});
                assert.strictEqual(maxSizeFunc.callCount, 1);
            });

            it('add an existing session', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Crab', 'Goyle'];
                var groupKey = 'foo';
                var errorMessage = 'Attept to add a session with an already existing ID on classic combos.';
                assert.throws(function() { tracker.addSession(_td.SESSION_ID, members, groupKey); },
                              errorMessage);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });

            it('add a session, buffer exceeds, dropping one', function() {
                var members = ['Graham Chapman', 'John Cleese', 'Terry Gilliam',
                               'Eric Idle', 'Terry Jones', 'Michael Palin'];
                var maxSizeFunc = stub().returns(1);
                var tracker = new ns.SessionTracker('Monty Python', maxSizeFunc);
                tracker.sessions = {'good skit': {
                                       members: members,
                                       groupKeys: ['unladen swallow'] }};
                tracker.sessionIDs = ['good skit'];
                tracker.addSession('another good skit', members, 'silly walk');
                assert.deepEqual(tracker.sessionIDs, ['another good skit']);
                assert.deepEqual(tracker.sessions,
                                 {'another good skit': {
                                     members: members,
                                     groupKeys: ['silly walk'] }});
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [30, ['Monty Python DROPPED session good skit at size 1, potential data loss.']]);
            });

            it('add a session, buffer exceeds, no drop', function() {
                var members = ['Graham Chapman', 'John Cleese', 'Terry Gilliam',
                               'Eric Idle', 'Terry Jones', 'Michael Palin'];
                var maxSizeFunc = stub().returns(1);
                var tracker = new ns.SessionTracker('Monty Python', maxSizeFunc, false);
                tracker.sessions = {'good skit': {
                                       members: members,
                                       groupKeys: ['unladen swallow'] }};
                tracker.sessionIDs = ['good skit'];
                tracker.addSession('another good skit', members, 'silly walk');
                assert.lengthOf(tracker.sessionIDs, 2);
                assert.lengthOf(Object.keys(tracker.sessions), 2);
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.session._log.getCall(0).args;
                assert.deepEqual(log, [20, ['Monty Python is 1 items over expected capacity.']]);
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
                var groupKey = _td.GROUP_KEY;
                tracker.update(_td.SESSION_ID, members, groupKey);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
            });

            it('new group key only', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Moe', 'Larry', 'Curly'];
                var groupKey = 'foo';
                tracker.update(_td.SESSION_ID, members, groupKey);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.lengthOf(tracker.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(tracker.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
            });

            it('mismatching participants', function() {
                var tracker = new ns.SessionTracker('classic combos', stub());
                tracker.sessionIDs = utils.clone(_td.SESSION_TRACKER.sessionIDs);
                tracker.sessions = utils.clone(_td.SESSION_TRACKER.sessions);
                var members = ['Crab', 'Goyle'];
                var groupKey = 'foo';
                var errorMessage = 'Attept to update classic combos with mis-matching members for a sesssion.';
                sandbox.stub(MegaLogger._logRegistry.assert, '_log');
                assert.throws(function() { tracker.update(_td.SESSION_ID, members, groupKey); },
                              errorMessage);
                assert.deepEqual(tracker.sessionIDs, _td.SESSION_TRACKER.sessionIDs);
                assert.deepEqual(tracker.sessions, _td.SESSION_TRACKER.sessions);
                var log = MegaLogger._logRegistry.assert._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });
        });
    });
});
