/**
 * @fileOverview
 * Test data for use with all the tests.
 */

"use strict";

/*
 * Created: 4 March 2014 Guy K. Kloss <gk@mega.co.nz>
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

var _td = {};

// Attempt to patch the problem with running the code in PhantomJS.
//Uint8Array = Array;

/* Constants mainly for the mpenc.greet.cliques. */

_td.C25519_PRIV_KEY = atob('bjsHiad/643YeCeLEjOowGBwUGx8k/beiJS76sHbBt0=');
_td.C25519_PUB_KEY = atob('DIli3SnI/F6gmhY4m3nkdqA15AUNMj7brLHtJjfv1To=');
_td.COMP_KEY = atob('CkRWHRHU3gHMJdYeVM2P9N4ivX0ulIO4GCCzhKSGuRg=');

/* Constants mainly for the mpenc.greet.ske. */

_td.ED25519_PRIV_KEY = atob('bDDSqoc56NfaeIWM47kxxbIqiOtXp7v/AwVvdJfiWWr=');
_td.ED25519_PUB_KEY = atob('h115tJ66YIVwnv35VAI99LRSX7nwVE5o2AOZz+sQEgA=');
_td.SIGNATURE = atob('vmd3bY3iNGacSU5gJI3YyqHH6jpK+no0J3eRlMFzD2Loy7BgzMstRUmE'
                     + 'Qf2HdwXjoXMB/1dcEtE6yHNUCTs/DQ==');
_td.SESSION_ID = atob('tmfwrDEJQq2dGb+yv1OVC6SIPOdqaEwju1J9++G/fJ8=');
_td.STATIC_PUB_KEY_DIR = {
    'get': function(key) { return _td.ED25519_PUB_KEY; }
};

/* Constants mainly for the mpenc.codec and mpenc.greet.handler. */

_td.GROUP_KEY = atob('Fla5bB1SQ2itQ+XRUXGAVg==');
_td.UPFLOW_MESSAGE_STRING = atob('AAMAQH9lQgRxX/CP3GnmTdx9qMYhQPUTr6hpng0xMRW'
                                 + 'FA2q0kmooW6DvM60CQzLhfb/pQiiGJNymoOMaVVWI'
                                 + 'b/CmMAwAAQABAQEAAAExAQEAATIBAgABAAEDAAExA'
                                 + 'QMAATIBAwABMwEDAAE0AQMAATUBAwABNgEEAAABBA'
                                 + 'AgDIli3SnI/F6gmhY4m3nkdqA15AUNMj7brLHtJjf'
                                 + 'v1ToBBQAgDIli3SnI/F6gmhY4m3nkdqA15AUNMj7b'
                                 + 'rLHtJjfv1ToBBgAgh115tJ66YIVwnv35VAI99LRSX'
                                 + '7nwVE5o2AOZz+sQEgA=');
_td.UPFLOW_MESSAGE_CONTENT = {
    source: '1',
    dest: '2',
    agreement: 'initial',
    flow: 'upflow',
    members: ['1', '2', '3', '4', '5', '6'],
    intKeys: [null, _td.C25519_PUB_KEY],
    nonces: [_td.C25519_PUB_KEY],
    pubKeys: [_td.ED25519_PUB_KEY],
    sessionSignature: null,
};
_td.UPFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.UPFLOW_MESSAGE_STRING) + '.';

_td.DOWNFLOW_MESSAGE_CONTENT = {
    source: '1',
    dest: '',
    flow: 'downflow',
    signingKey: _td.ED25519_PRIV_KEY,
};
_td.DOWNFLOW_MESSAGE_STRING = atob('AAMAQI+4+ywTxMQ5giEPU55Div9oWfr5IJdDXwP3rT'
                                   + 'HrBjyoa6mj2nZDedMdnQpZR9wPfGaCTQjq4FQ6PO'
                                   + 'dAwUl9nA4AAQABAQEAAAExAQEAAAECAAEBAQgAIG'
                                   + 'ww0qqHOejX2niFjOO5McWyKojrV6e7/wMFb3SX4l'
                                   + 'lq');
_td.DOWNFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DOWNFLOW_MESSAGE_STRING) + '.';

_td.DATA_MESSAGE_STRING = atob('AAMAQBbZH7g8RwA5uBY5jpCZEfq1uswpMy19w3u3mYYgVx'
                               + 'kgZUDkHhInbpcPkzg2Y+LMIIuF+gNq+QJm6KiLWZt7vw'
                               + 'EAAQABAQAEABCOz5FOWLlL1lqToMcPR+FdAAIAEPtZnp'
                               + 'dMqulL8kJ6D+pHRW4=');
_td.DATA_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DATA_MESSAGE_STRING) + '.';
_td.DATA_MESSAGE_CONTENT = {
    signature: 'xxx',
    signatureOk: true,
    protocol: undefined, // define this in tests
    iv: 'xxx',
    data: 'foo',
};
