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
    "megalogger",
    "chai",
    "sinon/assert",
    "sinon/sandbox",
    "sinon/spy",
    "sinon/stub",
], function(ns, MegaLogger, chai, sinon_assert, sinon_sandbox, sinon_spy, stub) {
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
    });
});
