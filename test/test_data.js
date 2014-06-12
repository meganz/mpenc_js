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

// "Alice" keys from jodid25519.dh compliance test.
_td.C25519_PRIV_KEY = atob('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=');
_td.C25519_PUB_KEY = atob('hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=');
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
_td.UPFLOW_MESSAGE_STRING = atob('AAMAQOlcYiDl+VO4x+0s+u/nRCH5Zw+PDtKeMdVSJIy9'
                                 + '7+ld8H+8/IkeAxnWfLbo6ux5B7aSwbl/MPO82lzejb'
                                 + '/1hA4AAQABAQEAAAExAQEAATIBAgABAAEDAAExAQMA'
                                 + 'ATIBAwABMwEDAAE0AQMAATUBAwABNgEEAAABBAAghS'
                                 + 'DwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoB'
                                 + 'BQAghSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066Spjq'
                                 + 'qbTmoBBgAg11qYAYKxCrfVS/7TyWQHOg7hcvPapiMl'
                                 + 'rwIaaPcHURo=');
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
_td.DOWNFLOW_MESSAGE_STRING = atob('AAMAQPL0g9ZLDNTIoBD9muQhE/A5EknWxPHhbFwWyK'
                                   + 'NB2muF/1oddTCRt/0ICgYUc/eLv6A4IZDd687Qfy'
                                   + 'EeIa7qLAoAAQABAQEAAAExAQEAAAECAAEBAQgAIJ'
                                   + '1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn'
                                   + '9g');
_td.DOWNFLOW_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DOWNFLOW_MESSAGE_STRING) + '.';

_td.DATA_MESSAGE_STRING = atob('AAMAQNBLfbZVCJekp1lkURd9+walmbyGqPwR+ClO6mXlQd'
                               + '0Jy+5bPs3wVZeTt0cbGY4m3zHYzrLgrugrLhQm+5hULA'
                               + 'QAAQABAQAEABCLi9SrBqYNNin1PWubiixmAAIAEIctiO'
                               + 'c5iLTYSe0vfkFgeno=');
_td.DATA_MESSAGE_STRING32 = atob('AAMAQBn0Oh6ALsxfVY802lN8P36V3G4COnLUFWQfDUnp'
                                 + 'HOUMmkyYxXRwn8CU9O1R6alL1k2dIrACA57gUQwOib'
                                 + 'EtKgoAAQABAQAEABDE5jdZPPbM0Few8D45bQkRAAIA'
                                 + 'IAWUr22uwq7XWGdAEmlEs3pxUbtawnovOvswjmzhnr'
                                 + 'PQ');
_td.DATA_MESSAGE_PAYLOAD = '?mpENC:' + btoa(_td.DATA_MESSAGE_STRING) + '.';
_td.DATA_MESSAGE_CONTENT = {
    signature: 'xxx',
    signatureOk: true,
    protocol: undefined, // define this in tests
    iv: 'xxx',
    data: 'foo',
};
