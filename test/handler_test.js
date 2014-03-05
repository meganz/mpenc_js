/**
 * @fileOverview
 * Test of the `mpenc.handler` module.
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

"use strict";

var assert = chai.assert;

//describe("module level", function() {
//    var ns = mpenc.handler;
//    
//    describe('xxx()', function() {
//        it('xxx', function() {
//            
//        });
//        
////        it('yyy', function() {
////            
////        });
//    });
//});

describe("ProtocolHandler class", function() {
    var ns = mpenc.handler;
    
    describe('constructor', function() {
        it('just make an instance', function() {
            var handler = new ns.ProtocolHandler('42', _td.RSA_PRIV_KEY, _td.RSA_PUB_KEY);
            assert.strictEqual(handler.id, '42');
        });
        
//        it('yyy', function() {
//            
//        });
    });
});
