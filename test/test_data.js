/**
 * @fileOverview
 * Test data for use with all the tests.
 */

"use strict";

/*
 * Created: 4 March 2014-2015 Guy K. Kloss <gk@mega.co.nz>
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

var _td = {};

/* Constants mainly for the mpenc.greet.cliques. */

// "Alice" keys from jodid25519.dh compliance test.
_td.C25519_PRIV_KEY = atob('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=');
_td.C25519_PUB_KEY = atob('hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=');
_td.BOB_PRIV = atob('XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=');
_td.BOB_PUB = atob('3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=');
_td.SECRET_KEY = atob('Sl2dW6TOLeFyjjv0gDUPJeB+IclH0Z4zdvCbPB4WF0I=');

_td.COMP_KEY = atob('CkRWHRHU3gHMJdYeVM2P9N4ivX0ulIO4GCCzhKSGuRg=');

/* Constants mainly for the mpenc.greet.ske. */

// First keys from jodid25519.eddsa compliance test.
_td.ED25519_PRIV_KEY = atob('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=');
_td.ED25519_PUB_KEY = atob('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=');
_td.SIGNATURE = atob('kokcn0EwadoZVOSusGBp2fN8mFGeV8L4TYXWV7Y0xNs41T98Kuyx55vK'
                     + 'HNxi6S4nt+BVT7r4i0p39sC5+xrPBg==');
_td.SESSION_ID = atob('tmfwrDEJQq2dGb+yv1OVC6SIPOdqaEwju1J9++G/fJ8=');
_td.STATIC_PUB_KEY_DIR = {
    'get': function(key) { return _td.ED25519_PUB_KEY; }
};

/* Constants mainly for the mpenc.codec and mpenc.greet.handler. */

_td.GROUP_KEY = atob('Fla5bB1SQ2itQ+XRUXGAVg==');
_td.UPFLOW_MESSAGE_STRING = atob('AAMAQNwWlkP2SKJmD5Hux2K9Itmn4z4duGJvt0Bm2LqM'
                                 + 'EusHgd/egLsz2rNmEjJ1YF+n0eGH7tUwHyJ6EZiWhF'
                                 + 'YE4QIAAQABAQAFAAIAnAEAAAExAQEAATIBAgABMQEC'
                                 + 'AAEyAQIAATMBAgABNAECAAE1AQIAATYBAwAAAQMAII'
                                 + 'Ug8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05q'
                                 + 'AQQAIIUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY'
                                 + '6qm05qAQUAINdamAGCsQq31Uv+08lkBzoO4XLz2qYj'
                                 + 'Ja8CGmj3B1Ea');
_td.UPFLOW_MESSAGE_CONTENT = {
    source: '1',
    dest: '2',
    messageType: '\u0000\u009c', // codec.MESSAGE_TYPE.INIT_INITIATOR_UP
    members: ['1', '2', '3', '4', '5', '6'],
    intKeys: ['', _td.C25519_PUB_KEY],
    nonces: [_td.C25519_PUB_KEY],
    pubKeys: [_td.ED25519_PUB_KEY],
    sessionSignature: null,
};
_td.UPFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.UPFLOW_MESSAGE_STRING) + '.';

_td.DOWNFLOW_MESSAGE_CONTENT = {
    source: '1',
    dest: '',
    messageType: '\u0000\u00d3', // codec.MESSAGE_TYPE.QUIT_DOWN
    signingKey: _td.ED25519_PRIV_KEY,
};
_td.DOWNFLOW_MESSAGE_STRING = atob('AAMAQMTL5erm9/6IBvW0/DeWrCrCrfdJJNcUwrGVH2'
                                   + 'LOq4en43DetGsHaDHve0VWTNTPcjzCdE0iiOUHQp'
                                   + 'Wjffirzw4AAQABAQAFAAIA0wEAAAExAQEAAAEHAC'
                                   + 'CdYbGd7/1aYLqESvSS7CzEREnFaXsyaRlwO6wDHK'
                                   + '5/YA==');
_td.DOWNFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DOWNFLOW_MESSAGE_STRING) + '.';

_td.SESSION_KEY_STORE = { sessionIDs: [_td.SESSION_ID],
                          sessions: {} };
_td.SESSION_KEY_STORE.sessions[_td.SESSION_ID] = {
    members: ['Moe', 'Larry', 'Curly'],
    groupKeys: [_td.GROUP_KEY]
};
_td.SESSION_KEY_STORE.pubKeyMap = { 'Moe': _td.ED25519_PUB_KEY };
_td.DATA_MESSAGE_STRING = atob('AAYAAVQAAwBAaLW0Axx5p0RVPvjoX0rug6m3VhqsGmX17M'
                               + 'Td1eSqdUBaCqwqAO2JfxGNM0p5xoPoQFltrdCGIRvK/Q'
                               + 'xskpTHBwABAAEBAAUAAgAAAAQADKqt+v306FvmeyO2+Q'
                               + 'ACAAVpTrLyDw==');
_td.DATA_MESSAGE_STRING2 = atob('AAYAAVQAAwBAGMIykFfRoNU9dFHGAUNRxMLSyRXC/7dQD'
                                + 'zUgtGZIVXUKN3qRbXqgM25Svcnx65gHeGk5i283yXJ7'
                                + 'BvWn7LmPCwABAAEBAAUAAgAAAAQADHG7NwPQuYjNyTl'
                                + 'uCwACAAV3yWhC0A==');
_td.DATA_MESSAGE_STRING32 = atob('AAYAAVQAAwBAGsqBp4p3VhODEBmaopnopJVPcg9hagE2'
                                 + 'HwaWinItoz2Rpj6ILojWLpTWVB53ruK5wrAuEZ+oKB'
                                 + 'ZqA75QTFcSCAABAAEBAAUAAgAAAAQADJoa55Rwav0Z'
                                 + 'HN+wWgACACBqKW02hYZ55ZgtjOq9Q0GkLYXEMmAYgj'
                                 + 'y06IRKaJqR0w==');
_td.DATA_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DATA_MESSAGE_STRING) + '.';
_td.DATA_MESSAGE_CONTENT = {
    signature: 'xxx',
    messageType: '\u0000\u0000', // codec.MESSAGE_TYPE.PARTICIPANT_DATA
    protocol: undefined, // define this in tests
    iv: 'xxx',
    data: 'foo',
};

_td.ERROR_MESSAGE_PAYLOAD = '?mpENC Error:'
                          + 'ztdjNtIVrMq0I487tIYqAYtKv/yhyfrYxk5EtKeHs9C2L3vgv'
                          + '+QlJ4tieMexM/T5AVefPyOQl4iKrYbw7hqMCA==:'
                          + 'from "a.dumbledore@hogwarts.ac.uk/android123":'
                          + 'TERMINAL:'
                          + 'Signature verification for'
                          + ' q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
