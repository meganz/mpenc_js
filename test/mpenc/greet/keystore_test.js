/**
 * @fileOverview
 * Test of the `mpenc/greet/keystore` module.
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
    "mpenc/greet/keystore",
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
        sandbox.stub(MegaLogger._logRegistry.keystore, '_log');
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("KeyStore class", function() {
        describe('constructor', function() {
            it('just make an instance', function() {
                var maxSizeFunc = stub();
                var store = new ns.KeyStore('James', maxSizeFunc);
                assert.strictEqual(store.name, 'James');
                assert.deepEqual(store.sessions, {});
                assert.deepEqual(store.sessionIDs, []);
                assert.deepEqual(store.pubKeyMap, {});
                assert.strictEqual(store.drop, true);
            });
        });

        describe('#addSession method', function() {
            it('add a first session', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub();
                var store = new ns.KeyStore('Three Stooges', maxSizeFunc);
                store.addSession('film debut', members, pubKeys, 'Soup to Nuts');
                assert.deepEqual(store.sessionIDs, ['film debut']);
                assert.deepEqual(store.sessions,
                                 {'film debut': {
                                     members: members,
                                     groupKeys: ['Soup to Nuts'] }});
                assert.deepEqual(store.pubKeyMap, pubKeysDir);
                assert.strictEqual(maxSizeFunc.callCount, 1);
            });

            it('add an existing session', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                var members = ['Vincent', 'Gregory'];
                var pubKeys = ['Crabbe', 'Goyle'];
                var pubKeysDir = {'Vincent': 'Crabbe', 'Gregory': 'Goyle'};
                var groupKey = 'foo';
                var errorMessage = 'Attempt to add a session with an already existing ID on classic combos.';
                assert.throws(function() { store.addSession(_td.SESSION_ID, members, pubKeys, groupKey); },
                              errorMessage);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.deepEqual(store.sessions, _td.SESSION_KEY_STORE.sessions);
                var log = MegaLogger._logRegistry.keystore._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });

            it('add a session, buffer exceeds, dropping one', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub().returns(1);
                var store = new ns.KeyStore('Three Stooges', maxSizeFunc);
                store.sessionIDs = ['film debut'];
                store.sessions = {'film debut': {
                                      members: members,
                                      groupKeys: ['Soup to Nuts'] }};
                store.pubKeyMap = pubKeysDir;
                store.addSession('second film', members, pubKeys, 'Nertsery Rhymes');
                assert.deepEqual(store.sessionIDs, ['second film']);
                assert.deepEqual(store.sessions,
                                 {'second film': {
                                     members: members,
                                     groupKeys: ['Nertsery Rhymes'] }});
                assert.deepEqual(store.pubKeyMap, pubKeysDir);
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.keystore._log.getCall(0).args;
                assert.deepEqual(log, [30, ['Three Stooges DROPPED session film debut at size 1, potential data loss.']]);
            });

            it('add a session, buffer exceeds, no drop', function() {
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var maxSizeFunc = stub().returns(1);
                var store = new ns.KeyStore('Three Stooges', maxSizeFunc, false);
                store.sessionIDs = ['film debut'];
                store.sessions = {'film debut': {
                                      members: members,
                                      groupKeys: ['Soup to Nuts'] }};
                store.pubKeyMap = pubKeysDir;
                store.addSession('second film', members, pubKeys, 'Nertsery Rhymes');
                assert.lengthOf(store.sessionIDs, 2);
                assert.lengthOf(Object.keys(store.sessions), 2);
                assert.strictEqual(maxSizeFunc.callCount, 1);
                var log = MegaLogger._logRegistry.keystore._log.getCall(0).args;
                assert.deepEqual(log, [20, ['Three Stooges is 1 items over expected capacity.']]);
            });
        });

        describe('#addGroupKey method', function() {
            it('add a group key to a session', function() {
                var members = ['The Doctor', 'Rose Tyler'];
                var maxSizeFunc = stub();
                var store = new ns.KeyStore('Doctor Who', maxSizeFunc);
                store.sessions = { 'Series 1': {
                                       members: members,
                                       groupKeys: ['Chris Eccleston'] } };
                store.sessionIDs = ['Series 1'];
                store.addGroupKey('Series 1', 'David Tennant');
                assert.deepEqual(store.sessions,
                                 { 'Series 1': {
                                       members: members,
                                       groupKeys: ['David Tennant', 'Chris Eccleston'] } });
            });

            it('duplicate group key for existing session', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                var members = ['Moe', 'Larry', 'Curly'];
                var groupKey = _td.GROUP_KEY;
                store.addGroupKey(_td.SESSION_ID, groupKey);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.deepEqual(store.sessions, _td.SESSION_KEY_STORE.sessions);
                var log = MegaLogger._logRegistry.keystore._log.getCall(0).args;
                assert.deepEqual(log, [20, ['classic combos ignores adding a group key already stored.']]);
            });

            it('new group key for non-latest session', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessionIDs.unshift('TARDIS');
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                store.sessions['TARDIS'] = {
                    members: ['The Doctor', 'Rose Tyler'],
                    groupKeys: ['Gallifrey']
                };
                store.addGroupKey(_td.SESSION_ID, 'foo');
                assert.lengthOf(store.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(store.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
                var log = MegaLogger._logRegistry.keystore._log.getCall(0).args;
                assert.deepEqual(log, [30, ['New group key added to non-current session on classic combos.']]);
            });
        });

        describe('#addGroupKeyLastSession method', function() {
            it('add a group key to a session', function() {
                var members = ['The Doctor', 'Rose Tyler'];
                var maxSizeFunc = stub();
                var store = new ns.KeyStore('Doctor Who', maxSizeFunc);
                store.sessions = { 'Series 1': {
                                       members: members,
                                       groupKeys: ['Chris Eccleston'] } };
                store.sessionIDs = ['Series 1'];
                store.addGroupKeyLastSession('David Tennant');
                assert.deepEqual(store.sessions,
                                 { 'Series 1': {
                                       members: members,
                                       groupKeys: ['David Tennant', 'Chris Eccleston'] } });
            });
        });

        describe('#update method', function() {
            it('new session', function() {
                var store = new ns.KeyStore('classic combos', stub());
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var groupKey = _td.GROUP_KEY;
                store.update(_td.SESSION_ID, members, pubKeys, groupKey);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.deepEqual(store.sessions, _td.SESSION_KEY_STORE.sessions);
            });

            it('new group key only', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                var members = ['Moe', 'Larry', 'Curly'];
                var pubKeys = ['Howard', 'Fine', 'Howard'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var groupKey = 'foo';
                store.update(_td.SESSION_ID, members, pubKeys, groupKey);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.lengthOf(store.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(store.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
            });

            it('new group key, reordered participants', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                var members = ['Moe', 'Curly', 'Larry'];
                var pubKeys = ['Howard', 'Howard', 'Fine'];
                var pubKeysDir = {'Moe': 'Howard', 'Larry': 'Fine', 'Curly': 'Howard'};
                var groupKey = 'foo';
                store.update(_td.SESSION_ID, members, pubKeys, groupKey);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.lengthOf(store.sessions[_td.SESSION_ID].groupKeys, 2);
                assert.strictEqual(store.sessions[_td.SESSION_ID].groupKeys[0], 'foo');
            });

            it('mismatching participants', function() {
                var store = new ns.KeyStore('classic combos', stub());
                store.sessionIDs = utils.clone(_td.SESSION_KEY_STORE.sessionIDs);
                store.sessions = utils.clone(_td.SESSION_KEY_STORE.sessions);
                var members = ['Vincent', 'Gregory'];
                var pubKeys = ['Crabbe', 'Goyle'];
                var pubKeysDir = {'Vincent': 'Crabbe', 'Gregory': 'Goyle'};
                var groupKey = 'foo';
                var errorMessage = 'Attempt to update classic combos with mis-matching members for a sesssion.';
                sandbox.stub(MegaLogger._logRegistry.assert, '_log');
                assert.throws(function() { store.update(_td.SESSION_ID, members, pubKeys, groupKey); },
                              errorMessage);
                assert.deepEqual(store.sessionIDs, _td.SESSION_KEY_STORE.sessionIDs);
                assert.deepEqual(store.sessions, _td.SESSION_KEY_STORE.sessions);
                var log = MegaLogger._logRegistry.assert._log.getCall(0).args;
                assert.deepEqual(log, [40, [errorMessage]]);
            });
        });
    });
});
