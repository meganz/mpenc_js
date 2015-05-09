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
_td.UPFLOW_MESSAGE_STRING = atob('AAMAQBTmYCWuBrUMDbKr7Ue8vKla0lHIzJ+dGSvBPdqG'
                                 + 'RWFP9WOCzUxtfdQ1H6VLoIuqRNJtYhWptglzcyCkrc'
                                 + '4jXAcAAQABAQACAAECAf8AAgCcAQAAATEBAQABMgEC'
                                 + 'AAExAQIAATIBAgABMwECAAE0AQIAATUBAgABNgEDAA'
                                 + 'ABAwAghSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066Sp'
                                 + 'jqqbTmoBBAAghSDwCYkwp1R0i33ctD73Wg2/Og0mOB'
                                 + 'r066SpjqqbTmoBBQAg11qYAYKxCrfVS/7TyWQHOg7h'
                                 + 'cvPapiMlrwIaaPcHURo=');

_td.UPFLOW_MESSAGE_CONTENT = {
    source: '1',
    dest: '2',
    messageType: '\x02', // codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE
    greetType: '\u0000\u009c', // greeter.GREET_TYPE.INIT_INITIATOR_UP
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
    messageType: '\x02', // codec.MESSAGE_TYPE.MPENC_GREET_MESSAGE
    greetType: '\u0000\u00d3', // greeter.GREET_TYPE.QUIT_DOWN
    signingKey: _td.ED25519_PRIV_KEY,
};
_td.DOWNFLOW_MESSAGE_STRING = atob('AAMAQEI7aL7VPi+ay79q4wImezN4Sc1qVmo1vUT3KZ'
                                   + 'z03btjuiiHHoN7H+nvWdtjoqWqn4Zuc6Gm7sPcfq'
                                   + 'bdLFsOPw0AAQABAQACAAECAf8AAgDTAQAAATEBAQ'
                                   + 'AAAQcAIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGX'
                                   + 'A7rAMcrn9g');

_td.DOWNFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DOWNFLOW_MESSAGE_STRING) + '.';

_td.SESSION_KEY_STORE = { sessionIDs: [_td.SESSION_ID],
                          sessions: {} };
_td.SESSION_KEY_STORE.sessions[_td.SESSION_ID] = {
    members: ['Moe', 'Larry', 'Curly'],
    groupKeys: [_td.GROUP_KEY]
};
_td.SESSION_KEY_STORE.pubKeyMap = { 'Moe': _td.ED25519_PUB_KEY,
                                    'Larry': _td.ED25519_PUB_KEY,
                                    'Curly': _td.ED25519_PUB_KEY };
_td.DATA_MESSAGE_STRING = atob('ABIAAVQAAwBAsqcfdFBp1P+ei9LTWIGpXn144fzi3UorsC'
                             + 'G7moGQzsoJFCJeLJYcj358uISQqRPej+nuscs7PPcMH58G'
                             + 'bn1iAwABAAEBAAIAAQMAEQAMevs2iGlNE8kspMvZABAACY'
                             + 'wQ7EMaeuivXg==');
_td.DATA_MESSAGE_STRING2 = atob('ABIAAVQAAwBAh/aR5NsEbF0bqwjdIjGCM11653LX07Lvc'
                              + 't86jiSuawHF63N21R8s/cP2WTl4/j2rVcDxnMAeqghnN0'
                              + 'NfI/GwAgABAAEBAAIAAQMAEQAMYEJcgRKug0h+aSSBABA'
                              + 'ACWT5Ftq26HvaBQ==');
_td.DATA_MESSAGE_STRING32 = atob('ABIAAVQAAwBAkJN7pyCATSef9Li1omFV4AKMf4y5koDM'
                               + 'Em5uEtwnT1D3WiMdJs2cA7dMh2JYo9lXtDBt1YadRmT4'
                               + 'cQwa7v3rCAABAAEBAAIAAQMAEQAMy3mFpbiHeD4F3n0u'
                               + 'ABAACfWUXRE7ijLczA==');

_td.DATA_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DATA_MESSAGE_STRING) + '.';
_td.DATA_MESSAGE_CONTENT = {
    signature: 'xxx',
    messageType: '\x03', // codec.MESSAGE_TYPE.MPENC_DATA_MESSAGE
    protocol: undefined, // define this in tests
    iv: 'xxx',
    data: 'foo',
};

_td.ERROR_MESSAGE_STRING = atob('AAMAQDGB8lrU5yOfEENSlv+Gtonq0DiwPg7rJcLbIeSF6'
                                 + 'PLlRhCOo0GZhbR6z0gNsPX9x7s8zNjLFh9Z0k6dLRR'
                                 + '3XwEAAQABAQACAAEEAQAAJmEuZHVtYmxlZG9yZUBob'
                                 + '2d3YXJ0cy5hYy51ay9hbmRyb2lkMTIzAgEAAQIAEAB'
                                 + 'MU2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmb3IgcS5xd'
                                 + 'WlycmVsbEBob2d3YXJ0cy5hYy51ay93cDhwb3NzZXN'
                                 + 'zZWQ2NjYgZmFpbGVkLg==');
