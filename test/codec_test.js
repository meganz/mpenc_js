/**
 * @fileOverview
 * Test of the `mpenc.codec` module.
 */

/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
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

(function() {
    "use strict";

    var assert = chai.assert;
    var ns = mpenc.codec;
    
    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;
    
    beforeEach(function() {
        sandbox = sinon.sandbox.create();
    });
    
    afterEach(function() {
        sandbox.restore();
    });
    
    var UPFLOW_MESSAGE_STRING = atob('AQAAATEBAQABMgECAAEAAQMAATEBAwABMgEDAAEz'
                                     + 'AQMAATQBAwABNQEDAAE2AQQAAAEEACBqmYo4w/'
                                     + 'GJ7VtkY2BRKhOVfE2H35PtNLM7Xxh+oVEJTQEF'
                                     + 'ACBqmYo4w/GJ7VtkY2BRKhOVfE2H35PtNLM7Xx'
                                     + 'h+oVEJTQEGACBWJukhW6F/4M8j9caOl+li7dcO'
                                     + 'yZBbdT2rBXlZ74YHEgEHAAA=');
    var UPFLOW_MESSAGE_CONTENT = {
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
    var UPFLOW_MESSAGE_WIRE = '?mpENC:' + btoa(UPFLOW_MESSAGE_STRING) + '.';
    
    describe("module level TLV stuff", function() {
        describe("_short2bin()", function() {
            it('just convert', function() {
                var values = [0, 42, 1234, 21356];
                var expected = ['\u0000\u0000', '\u0000\u002a', '\u0004\u00d2', 'Sl'];
                for (var i = 0; i < values.length; i++) {
                    assert.strictEqual(ns._short2bin(values[i]), expected[i]);
                }
            });
        });
        
        describe("_bin2short()", function() {
            it('just convert', function() {
                var values = ['\u0000\u0000', '\u0000\u002a', '\u0004\u00d2', 'Sl'];
                var expected = [0, 42, 1234, 21356];
                for (var i = 0; i < values.length; i++) {
                    assert.strictEqual(ns._bin2short(values[i]), expected[i]);
                }
            });
        });
        
        describe("encodeTLV()", function() {
            it('null equivalent', function() {
                assert.strictEqual(ns.encodeTLV(0, ''), '\u0000\u0000\u0000\u0000');
            });
            
            it('some examples', function() {
                var tests = [[0, 'hello'],
                             [42, "Don't panic!"],
                             [21356, _td.SESSION_ID],
                             [14, null]];
                var expected = ['\u0000\u0000\u0000\u0005hello',
                                "\u0000\u002a\u0000\u000cDon't panic!",
                                'Sl\u0000\u0020' + _td.SESSION_ID,
                                '\u0000\u000e\u0000\u0000'];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.encodeTLV(tests[i][0], tests[i][1]);
                    assert.strictEqual(result, expected[i]);
                }
            });
        });
        
        describe("_encodeTlvArray()", function() {
            it('null content equivalents', function() {
                var tests = [[''], [null]];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns._encodeTlvArray(0, tests[i]);
                    assert.strictEqual(result, '\u0000\u0000\u0000\u0000');
                }
            });
            
            it('null equivalents', function() {
                var tests = [[], null];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns._encodeTlvArray(0, tests[i]);
                    assert.strictEqual(result, '');
                }
            });
            
            it('passed in non-array', function() {
                assert.throws(function() { ns._encodeTlvArray(0, '42'); },
                              'Value passed neither an array or null.');
            });
            
            it('some examples', function() {
                var result = ns._encodeTlvArray(42, ['1', '22', '333']);
                assert.strictEqual(result,
                                     '\u0000\u002a\u0000\u00011'
                                   + '\u0000\u002a\u0000\u000222'
                                   + '\u0000\u002a\u0000\u0003333');
            });
        });
        
        describe("decodeTLV()", function() {
            it('null equivalent', function() {
                var result = ns.decodeTLV('\u0000\u0000\u0000\u0000');
                assert.strictEqual(result.type, 0);
                assert.strictEqual(result.value, null);
            });
            
            it('some examples', function() {
                var tests = ['\u0000\u0000\u0000\u0005hello',
                             "\u0000\u002a\u0000\u000cDon't panic!",
                             'Sl\u0000\u0020' + _td.SESSION_ID,
                             '\u0000\u0000\u0000\u0005hello\u0000\u0000\u0000\u0005world'];
                var expected = [[0, 'hello', ''],
                                [42, "Don't panic!", ''],
                                [21356, _td.SESSION_ID, ''],
                                [0, 'hello', '\u0000\u0000\u0000\u0005world']];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.decodeTLV(tests[i]);
                    assert.strictEqual(result.type, expected[i][0]);
                    assert.strictEqual(result.value, expected[i][1]);
                    assert.strictEqual(result.rest, expected[i][2]);
                }
            });
            
            it('misformed TLV', function() {
                assert.throws(function() { ns.decodeTLV('\u0000\u0000\u0000\u0005hell'); },
                              'TLV payload length does not match indicated length.');
            });
        });
        
        describe("encodeMessageContent()", function() {
            it('upflow message', function() {
                sandbox.stub(mpenc.codec, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
                var result = ns.encodeMessageContent(UPFLOW_MESSAGE_CONTENT);
                assert.lengthOf(result, 56);
            });
            
            it('upflow message binary', function() {
                var result = ns.encodeMessageContent(UPFLOW_MESSAGE_CONTENT);
                assert.strictEqual(result, UPFLOW_MESSAGE_STRING);
            });
        });
        
        describe("decodeMessageContent()", function() {
            it('upflow message', function() {
                var result = ns.decodeMessageContent(UPFLOW_MESSAGE_STRING);
                assert.strictEqual(result.source, UPFLOW_MESSAGE_CONTENT.source);
                assert.strictEqual(result.dest, UPFLOW_MESSAGE_CONTENT.dest);
                assert.strictEqual(result.agreement, UPFLOW_MESSAGE_CONTENT.agreement);
                assert.strictEqual(result.flow, UPFLOW_MESSAGE_CONTENT.flow);
                assert.deepEqual(result.members, UPFLOW_MESSAGE_CONTENT.members);
                assert.deepEqual(result.intKeys, UPFLOW_MESSAGE_CONTENT.intKeys);
                assert.deepEqual(result.nonces, UPFLOW_MESSAGE_CONTENT.nonces);
                assert.deepEqual(result.pubKeys, UPFLOW_MESSAGE_CONTENT.pubKeys);
                assert.strictEqual(result.sessionSignature, UPFLOW_MESSAGE_CONTENT.sessionSignature);
            });
        });
    });
    
    describe("encodeMessage()", function() {
        it('upflow message', function() {
            var message = {
                source: '1',
                dest: '2',
                agreement: 'initial',
                flow: 'upflow',
                members: ['1', '2', '3', '4', '5', '6'],
                intKeys: [null, _td.C25519_PUB_KEY],
                nonces: [_td.C25519_PUB_KEY],
                pubKeys: [_td.ED25519_PUB_KEY],
                sessionSignature: null
            };
            sandbox.stub(mpenc.codec, 'encodeTLV').returns('\u0000\u0000\u0000\u0000');
            var result = ns.encodeMessage(message);
            assert.strictEqual(result, '?mpENC:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=.');
        });
        
        it('upflow message binary', function() {
            var message = {
                source: '1',
                dest: '2',
                agreement: 'initial',
                flow: 'upflow',
                members: ['1', '2', '3', '4', '5', '6'],
                intKeys: [null, _td.C25519_PUB_KEY],
                nonces: [_td.C25519_PUB_KEY],
                pubKeys: [_td.ED25519_PUB_KEY],
                sessionSignature: null
            };
            var result = ns.encodeMessage(message);
            assert.strictEqual(result, UPFLOW_MESSAGE_WIRE);
        });
        
        it('null message', function() {
            assert.strictEqual(ns.encodeMessage(null), null);
            assert.strictEqual(ns.encodeMessage(undefined), null);
        });
    });
    
    describe("decodeMessage()", function() {
        it('upflow message', function() {
            var result = ns.decodeMessage(UPFLOW_MESSAGE_WIRE);
            assert.strictEqual(result.source, UPFLOW_MESSAGE_CONTENT.source);
            assert.strictEqual(result.dest, UPFLOW_MESSAGE_CONTENT.dest);
            assert.strictEqual(result.agreement, UPFLOW_MESSAGE_CONTENT.agreement);
            assert.strictEqual(result.flow, UPFLOW_MESSAGE_CONTENT.flow);
            assert.deepEqual(result.members, UPFLOW_MESSAGE_CONTENT.members);
            assert.deepEqual(result.intKeys, UPFLOW_MESSAGE_CONTENT.intKeys);
            assert.deepEqual(result.nonces, UPFLOW_MESSAGE_CONTENT.nonces);
            assert.deepEqual(result.pubKeys, UPFLOW_MESSAGE_CONTENT.pubKeys);
            assert.strictEqual(result.sessionSignature, UPFLOW_MESSAGE_CONTENT.sessionSignature);
        });
        
        it('null message', function() {
            assert.strictEqual(ns.decodeMessage(null), null);
            assert.strictEqual(ns.decodeMessage(undefined), null);
        });
    });
    
    describe("encryptDataMessage()", function() {
        it('null equivalents', function() {
            var key = djbec.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.encryptDataMessage(tests[i], key), null);
            }
        });
        
        it('data messages', function() {
            var iv = asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f');
            var key = djbec.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn"];
            var expected = ['ZZBBd/VfkkxbQjQnJs2XVw==',
                            'hPZ6wa6Sco8iO4tJUfiQwQ==',
                            'IGX/B9/06eKjM/v2xiXPaA==',
                            'fSeQGNTTe+eUismz9dhnAgwyJjA/dUBmkgwuX/aB6Vc=',
                            'XmawppTzWIAuwn5sNffET4Dzbk86g4NQ6ySQO+baKwzsZGjIqxlRTz0jdufBUN6deCOG1yKZUOsskk1hcpzTzQ=='];
            sandbox.stub(mpenc.utils, '_newKey08').returns(iv);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.encryptDataMessage(tests[i], key);
                assert.strictEqual(result.iv, djbec.bytes2string(iv));
                assert.strictEqual(btoa(result.data), expected[i]);
            }
        });
    });
    
    describe("decryptDataMessage()", function() {
        it('null equivalents', function() {
            var iv = djbec.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f'));
            var key = djbec.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.decryptDataMessage(tests[i], key, iv), null);
            }
        });
        
        it('data messages', function() {
            var iv = djbec.bytes2string(asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f'));
            var key = djbec.bytes2string(asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'));
            var tests = ['ZZBBd/VfkkxbQjQnJs2XVw==',
                         'hPZ6wa6Sco8iO4tJUfiQwQ==',
                         'IGX/B9/06eKjM/v2xiXPaA==',
                         'fSeQGNTTe+eUismz9dhnAgwyJjA/dUBmkgwuX/aB6Vc=',
                         'XmawppTzWIAuwn5sNffET4Dzbk86g4NQ6ySQO+baKwzsZGjIqxlRTz0jdufBUN6deCOG1yKZUOsskk1hcpzTzQ=='];
            var expected = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                            "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn"];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.decryptDataMessage(atob(tests[i]), key, iv);
                assert.strictEqual(result, expected[i]);
            }
        });
    });
    
    describe("encryptDataMessage()/decryptDataMessage()", function() {
        it('10 round trips', function() {
            for (var i = 0; i < 5; i++) {
                var key = djbec.bytes2string(mpenc.utils._newKey08(128));
                var messageLength = Math.floor(256 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var encryptResult = ns.encryptDataMessage(message, key);
                var cipher = encryptResult.data;
                var iv = encryptResult.iv;
                var clear = ns.decryptDataMessage(cipher, key, iv);
                assert.strictEqual(message, clear);
            }
        });
    });
    
    describe("signDataMessage()", function() {
        it('null equivalents', function() {
            var tests = [null, undefined];
            for (var i = 0; i < tests.length; i++) {
                assert.strictEqual(ns.signDataMessage(tests[i],
                                                      _td.ED25519_PRIV_KEY,
                                                      _td.ED25519_PUB_KEY), null);
            }
        });
        
        it('data messages', function() {
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn"];
            var expected = ['74XflUXiebsofcIbUM9hl32bFZ+pGV3ZIgsg96mhdEp3EbX+uB+Ti1tEHKwHaCtcQwSioYzDeki6ijattbvkDA==',
                            'HOcWT2UCbCNrps4zOclKia1ZRvsgFHpkPE+3m2401BsRjBq+4vSGLErey9X82I5R0T6iocatWWQfuQjxvDDRDg==',
                            'lbQ8SmTH0pFF25NThHYBkchQcFcxMF9aG33qgG5TBJIFWXyIVAv2ASE0PLoC/EG13RFLBBHvkkyjNIpQW+ugAA==',
                            'sniCFEWWWGDsAXVqwRYuaOCexaag9o1TDEfsg5R4he22iyu7bULTqB9R3ueEdhTVLOKmz0XZU4BPlpzl235wCQ==',
                            'oEDxuOeRJL3e66mgWZA2B/OJLMqvilI74MrjzSpgaW6KhxXj9de/aGpon1C7jivCWGycUcdeHI/pchNU3hvvAw=='];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.signDataMessage(tests[i],
                                                _td.ED25519_PRIV_KEY,
                                                _td.ED25519_PUB_KEY);
                assert.strictEqual(btoa(result), expected[i]);
            }
        });
    });
    
    describe("verifyDataMessage()", function() {
        it('verifies', function() {
            var tests = ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn"];
            var signatures = ['74XflUXiebsofcIbUM9hl32bFZ+pGV3ZIgsg96mhdEp3EbX+uB+Ti1tEHKwHaCtcQwSioYzDeki6ijattbvkDA==',
                              'HOcWT2UCbCNrps4zOclKia1ZRvsgFHpkPE+3m2401BsRjBq+4vSGLErey9X82I5R0T6iocatWWQfuQjxvDDRDg==',
                              'lbQ8SmTH0pFF25NThHYBkchQcFcxMF9aG33qgG5TBJIFWXyIVAv2ASE0PLoC/EG13RFLBBHvkkyjNIpQW+ugAA==',
                              'sniCFEWWWGDsAXVqwRYuaOCexaag9o1TDEfsg5R4he22iyu7bULTqB9R3ueEdhTVLOKmz0XZU4BPlpzl235wCQ==',
                              'oEDxuOeRJL3e66mgWZA2B/OJLMqvilI74MrjzSpgaW6KhxXj9de/aGpon1C7jivCWGycUcdeHI/pchNU3hvvAw=='];
            for (var i = 0; i < tests.length; i++) {
                assert.ok(ns.verifyDataMessage(tests[i],
                                               atob(signatures[i]),
                                               _td.ED25519_PUB_KEY));
            }
        });
        it('failes verification', function() {
            var tests = ["Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         '', '42', "Don't panic!", 'Flying Spaghetti Monster'];
            var signatures = ['74XflUXiebsofcIbUM9hl32bFZ+pGV3ZIgsg96mhdEp3EbX+uB+Ti1tEHKwHaCtcQwSioYzDeki6ijattbvkDA==',
                              'HOcWT2UCbCNrps4zOclKia1ZRvsgFHpkPE+3m2401BsRjBq+4vSGLErey9X82I5R0T6iocatWWQfuQjxvDDRDg==',
                              'lbQ8SmTH0pFF25NThHYBkchQcFcxMF9aG33qgG5TBJIFWXyIVAv2ASE0PLoC/EG13RFLBBHvkkyjNIpQW+ugAA==',
                              'sniCFEWWWGDsAXVqwRYuaOCexaag9o1TDEfsg5R4he22iyu7bULTqB9R3ueEdhTVLOKmz0XZU4BPlpzl235wCQ==',
                              'oEDxuOeRJL3e66mgWZA2B/OJLMqvilI74MrjzSpgaW6KhxXj9de/aGpon1C7jivCWGycUcdeHI/pchNU3hvvAw=='];
            for (var i = 0; i < tests.length; i++) {
                assert.notOk(ns.verifyDataMessage(tests[i],
                                                  atob(signatures[i]),
                                                  _td.ED25519_PUB_KEY));
            }
        });
    });
    
    describe("signDataMessage()/verifyDataMessage()", function() {
        it('10 round trips', function() {
            for (var i = 0; i < 5; i++) {
                var privKey = djbec.bytes2string(mpenc.utils._newKey08(512));
                var pubKey = djbec.bytes2string(djbec.publickey(privKey));
                var messageLength = Math.floor(256 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var signature = ns.signDataMessage(message, privKey, pubKey);
                assert.ok(message, signature, pubKey);
            }
        });
    });
})();
