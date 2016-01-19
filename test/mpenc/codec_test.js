/**
 * @fileOverview
 * Test of the `mpenc/codec` module.
 */

/*
 * Created: 19 Mar 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014-2016 by Mega Limited, Auckland, New Zealand
 *     https://mega.nz/
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
    "mpenc/codec",
    "mpenc/version",
    "mpenc/helper/utils",
    "asmcrypto",
    "tweetnacl",
    "megalogger",
    "chai",
    "sinon/sandbox",
    "sinon/assert",
], function(ns, version, utils, asmCrypto, nacl, MegaLogger,
            chai, sinon_sandbox, sinon_assert) {
    "use strict";

    var assert = chai.assert;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon_sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

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
                var tests = ['', null, undefined];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.encodeTLV(0, tests[i]);
                    assert.strictEqual(result, '\u0000\u0000\u0000\u0000');
                }
                assert.strictEqual(ns.encodeTLV(0), '\u0000\u0000\u0000\u0000');
            });

            it('some examples', function() {
                var tests = [[0, 'hello'],
                             [42, "Don't panic!"],
                             [21356, _td.SESSION_ID],
                             [14, ''],
                             [14, null],
                             [1, '\u0001'],
                             [14, 0]];
                var expected = ['\u0000\u0000\u0000\u0005hello',
                                "\u0000\u002a\u0000\u000cDon't panic!",
                                'Sl\u0000\u0020' + _td.SESSION_ID,
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u000e\u0000\u0000',
                                '\u0000\u0001\u0000\u0001\u0001',
                                '\u0000\u000e\u0000\u0001\u0030'];
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
                assert.strictEqual(result.value, '');
            });

            it('some examples', function() {
                var tests = ['\u0000\u0000\u0000\u0005hello',
                             "\u0000\u002a\u0000\u000cDon't panic!",
                             'Sl\u0000\u0020' + _td.SESSION_ID,
                             '\u0000\u000e\u0000\u0000***',
                             '\u0000\u000e\u0000\u0001\u0030',
                             '\u0000\u0000\u0000\u0005hello\u0000\u0000\u0000\u0005world'];
                var expected = [[0, 'hello', ''],
                                [42, "Don't panic!", ''],
                                [21356, _td.SESSION_ID, ''],
                                [14, '', '***'],
                                [14, '0', ''],
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
                              'TLV payload length does not match indicated length: type 0; expected 5; actual 4');
            });
        });

        describe("decodeWirePacket()", function() {
            it('normal types', function() {
                var tests = ['Klaatu barada nikto.',
                             ns.encodeWirePacket(ns.MPENC_QUERY_MESSAGE),
                             _td.DOWNFLOW_MESSAGE_PAYLOAD,
                             _td.DATA_MESSAGE_PAYLOAD,
                             ns.encodeWirePacket(_td.ERROR_MESSAGE_STRING)];
                var expected = [[ns.MESSAGE_TYPE.PLAIN, 'Klaatu barada nikto.'],
                                [ns.MESSAGE_TYPE.MPENC_QUERY, ns.MPENC_QUERY_MESSAGE],
                                [ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE, _td.DOWNFLOW_MESSAGE_STRING],
                                [ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE, _td.DATA_MESSAGE_STRING],
                                [ns.MESSAGE_TYPE.MPENC_ERROR, _td.ERROR_MESSAGE_STRING]];
                for (var i = 0; i < tests.length; i++) {
                    var result = ns.decodeWirePacket(tests[i]);
                    assert.strictEqual(result.type, expected[i][0]);
                    assert.strictEqual(result.content, expected[i][1]);
                }
            });

            it('unknown message', function() {
                assert.throws(function() { ns.decodeWirePacket('?mpENC...blah.'); },
                              'Unknown mpENC message.');
            });

            it('null message', function() {
                var tests = [null, undefined, ''];
                for (var i = 0; i < tests.length; i++) {
                    assert.strictEqual(ns.decodeWirePacket(tests[i]), null);
                }
            });
        });
    });

    describe("encodeErrorMessage()", function() {
        it('with signature', function() {
            var from = 'a.dumbledore@hogwarts.ac.uk/android123';
            var message = 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
            sandbox.spy(ns, 'signMessage');
            var result = ns.encodeErrorMessage({
                from: from,
                severity: ns.ERROR.TERMINAL,
                message: message
            }, _td.ED25519_PRIV_KEY, _td.ED25519_PUB_KEY);
            sinon_assert.calledOnce(ns.signMessage);
            assert.strictEqual(btoa(result), btoa(_td.ERROR_MESSAGE_STRING));
        });

        it('without signature', function() {
            var from = 'a.dumbledore@hogwarts.ac.uk/android123';
            var message = 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.';
            sandbox.spy(ns, 'signMessage');
            var result = ns.encodeErrorMessage({
                from: from,
                severity: ns.ERROR.TERMINAL,
                message: message
            });
            assert.strictEqual(ns.signMessage.callCount, 0);
            assert.strictEqual(result, _td.ERROR_MESSAGE_STRING.slice(68));
        });
    });

    describe('#decodeErrorMessage() method', function() {
        it('processing for a signed error message', function() {
            var compare = { signatureOk: false,
                            from: 'a.dumbledore@hogwarts.ac.uk/android123',
                            severity: ns.ERROR.TERMINAL,
                            message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.',
                            signature: atob('MYHyWtTnI58QQ1KW/4a2ierQOLA+Duslwtsh5IXo8uVGEI6jQZmFtHrPSA2w9f3HuzzM2MsWH1nSTp0tFHdfAQ==') };
            sandbox.stub(ns, 'verifyMessageSignature').returns(false);
            var result = ns.decodeErrorMessage(_td.ERROR_MESSAGE_STRING,
                                               function() { return _td.ED25519_PUB_KEY; });
            sinon_assert.calledOnce(ns.verifyMessageSignature);
            assert.strictEqual(ns.verifyMessageSignature.getCall(0).args[1],
                               _td.ERROR_MESSAGE_STRING.slice(68));
            assert.deepEqual(result, compare);
        });

        it('processing for an unsigned error message', function() {
            var compare = { signatureOk: null,
                            from: 'a.dumbledore@hogwarts.ac.uk/android123',
                            severity: ns.ERROR.TERMINAL,
                            message: 'Signature verification for q.quirrell@hogwarts.ac.uk/wp8possessed666 failed.'};
            sandbox.spy(ns, 'verifyMessageSignature');
            var result = ns.decodeErrorMessage(_td.ERROR_MESSAGE_STRING.slice(68));
            assert.strictEqual(ns.verifyMessageSignature.callCount, 0);
            assert.deepEqual(result, compare);
        });
    });

    describe("signMessage()", function() {
        it('greet messages', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS'];
            var expected = ['tSkjLPe/o3LaK4z7ISbgJ5kaB9Uur2b1udT/ExWyEKJ8u6XrHt0rHXeA+pCWsMBLFX5Z65s68AoG0SwuxxfZBQ==',
                            'r2k2hjt17F+h3auY3CepMTtfN+9Ypqbnzd6ECFTWEgaGLjxT6cM5KC8z41PvgTQrVxPbBDKgFq8sA9zyH8r2Cw==',
                            'CcjivUm4ukFsau8okpUdbszVCtE637KaMlxq5556VAJhBJvUSE4efM7aR4Q4D3Nv9vmvaKfd0jFn6Scz4lOkDg==',
                            'Ndvyun9LRBs0i3n/D3QK/GlIulvKOYpJOTlfc67+/UEf+7T+osZCdqbB3NErLJeq/jU3TnTqlkIbmIOSRw2pBQ==',
                            'uGXHKElm/jKenaSxDsoK+CN5zsL4DNPCvYCjtWq35PuvgWFCPWR+dDMn/XwA6xeVGq+gQnYp88AH3WnH/04wCA=='];
            for (var i = 0; i < tests.length; i++) {
                var result = ns.signMessage(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                            tests[i], _td.ED25519_PRIV_KEY,  _td.ED25519_PUB_KEY);
                assert.strictEqual(btoa(result), expected[i], 'case ' + (i + 1));
            }
        });

        it('data messages', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS'];
            var expected = ['YnqS5BCXee/AGrIiswWsdCC2ghGRQjH5X8+fr6Izk10eAW4d6O4BKJa7CPrQRjFtYxqPR0DGG+pH1IM/wqy2Cw==',
                            'EK33UQGC6uMd5vsJzA8uPdXpfBsXbQtR+RusoDwA5r3V3ezOMldElxj2E2JPzFPtetWsM5iRWETkbqJVLJdPAg==',
                            'wezAkC2t4r1itjhj2CnLFSsHFqSQd4o3inyBsZpFUTSI7ntyTArYOUP5Va9oF77maxmGTLOnzDprGeTH9nutBA==',
                            '0nMt3jmAnyWCpZPBIk+x8rrb2xzIonKnOwvCJnXlT/6Ea7jXE+MWE4jdbHJyteWLs6C8pjSkFDpqSmcSzQaxDw==',
                            'bydUAaMI8sTat+8krksNVkbyRvkYmmJh3M1D+i9PCW72JbTmEuYforlNzgriDeDSunRRc4ZhdihW1uMpTVg8AQ=='];
            var sidkeyHash = utils.sha256(_td.SESSION_ID + _td.GROUP_KEY);
            for (var i = 0; i < tests.length; i++) {
                var result = ns.signMessage(ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE,
                                            tests[i], _td.ED25519_PRIV_KEY,  _td.ED25519_PUB_KEY,
                                            sidkeyHash);
                assert.strictEqual(btoa(result), expected[i], 'case ' + (i + 1));
            }
        });
    });

    describe("verifyMessageSignature()", function() {
        it('verifies greet message', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS']; // <-- this should verify!!!
            var signatures = ['tSkjLPe/o3LaK4z7ISbgJ5kaB9Uur2b1udT/ExWyEKJ8u6XrHt0rHXeA+pCWsMBLFX5Z65s68AoG0SwuxxfZBQ==',
                              'r2k2hjt17F+h3auY3CepMTtfN+9Ypqbnzd6ECFTWEgaGLjxT6cM5KC8z41PvgTQrVxPbBDKgFq8sA9zyH8r2Cw==',
                              'CcjivUm4ukFsau8okpUdbszVCtE637KaMlxq5556VAJhBJvUSE4efM7aR4Q4D3Nv9vmvaKfd0jFn6Scz4lOkDg==',
                              'Ndvyun9LRBs0i3n/D3QK/GlIulvKOYpJOTlfc67+/UEf+7T+osZCdqbB3NErLJeq/jU3TnTqlkIbmIOSRw2pBQ==',
                              'uGXHKElm/jKenaSxDsoK+CN5zsL4DNPCvYCjtWq35PuvgWFCPWR+dDMn/XwA6xeVGq+gQnYp88AH3WnH/04wCA=='];
            for (var i = 0; i < tests.length; i++) {
                assert.ok(ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                                    tests[i], atob(signatures[i]), _td.ED25519_PUB_KEY),
                          'case ' + (i + 1));
            }
        });

        it('failes verification greet message', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS'];
            var signatures = ['euj54DQbUVg0SyWlce5MYDowHU6j84FLY26VGap0ZxRJdVKzHOEpSLqrnB6XyaMSPJfi2LEJPYgbqhcPK86ZBg==',
                              'tSkjLPe/o3LaK4z7ISbgJ5kaB9Uur2b1udT/ExWyEKJ8u6XrHt0rHXeA+pCWsMBLFX5Z65s68AoG0SwuxxfZBQ==',
                              'r2k2hjt17F+h3auY3CepMTtfN+9Ypqbnzd6ECFTWEgaGLjxT6cM5KC8z41PvgTQrVxPbBDKgFq8sA9zyH8r2Cw==',
                              'CcjivUm4ukFsau8okpUdbszVCtE637KaMlxq5556VAJhBJvUSE4efM7aR4Q4D3Nv9vmvaKfd0jFn6Scz4lOkDg==',
                              'Ndvyun9LRBs0i3n/D3QK/GlIulvKOYpJOTlfc67+/UEf+7T+osZCdqbB3NErLJeq/jU3TnTqlkIbmIOSRw2pBQ=='];
            for (var i = 0; i < tests.length; i++) {
                assert.notOk(ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                                       tests[i], atob(signatures[i]), _td.ED25519_PUB_KEY),
                             'case ' + (i + 1));
            }
        });

        it('verifies data message', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS']; // <-- this should verify!!!
            var signatures = ['YnqS5BCXee/AGrIiswWsdCC2ghGRQjH5X8+fr6Izk10eAW4d6O4BKJa7CPrQRjFtYxqPR0DGG+pH1IM/wqy2Cw==',
                              'EK33UQGC6uMd5vsJzA8uPdXpfBsXbQtR+RusoDwA5r3V3ezOMldElxj2E2JPzFPtetWsM5iRWETkbqJVLJdPAg==',
                              'wezAkC2t4r1itjhj2CnLFSsHFqSQd4o3inyBsZpFUTSI7ntyTArYOUP5Va9oF77maxmGTLOnzDprGeTH9nutBA==',
                              '0nMt3jmAnyWCpZPBIk+x8rrb2xzIonKnOwvCJnXlT/6Ea7jXE+MWE4jdbHJyteWLs6C8pjSkFDpqSmcSzQaxDw==',
                              'bydUAaMI8sTat+8krksNVkbyRvkYmmJh3M1D+i9PCW72JbTmEuYforlNzgriDeDSunRRc4ZhdihW1uMpTVg8AQ=='];
            var sidkeyHash = utils.sha256(_td.SESSION_ID + _td.GROUP_KEY);
            for (var i = 0; i < tests.length; i++) {
                assert.ok(ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE,
                                                    tests[i], atob(signatures[i]), _td.ED25519_PUB_KEY,
                                                    sidkeyHash),
                          'case ' + (i + 1));
            }
        });

        it('failes verification data message', function() {
            var tests = ['42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'AAEAAQEBAAABMQEBAAEyAQIAAQABAwABMQEDAAEyAQMAATMBAwABNAEDAAE1AQMAATYBBAAAAQQAIGqZijjD8YntW2RjY'
                         + 'FEqE5V8TYffk+00sztfGH6hUQlNAQUAIGqZijjD8YntW2RjYFEqE5V8TYffk+00sztfGH6hUQlNAQYAIFYm6SFboX/g'
                         + 'zyP1xo6X6WLt1w7JkFt1PasFeVnvhgcS'];
            var signatures = ['H8r5iOernxktNJEE7cOyKGrfzHDg0JzyKXW275H6ScKdyyzG4TnaxO8qN8WmOrt7DNfRcjjmQ75FJz9kU1JcDg==',
                              'YnqS5BCXee/AGrIiswWsdCC2ghGRQjH5X8+fr6Izk10eAW4d6O4BKJa7CPrQRjFtYxqPR0DGG+pH1IM/wqy2Cw==',
                              'EK33UQGC6uMd5vsJzA8uPdXpfBsXbQtR+RusoDwA5r3V3ezOMldElxj2E2JPzFPtetWsM5iRWETkbqJVLJdPAg==',
                              'wezAkC2t4r1itjhj2CnLFSsHFqSQd4o3inyBsZpFUTSI7ntyTArYOUP5Va9oF77maxmGTLOnzDprGeTH9nutBA==',
                              '0nMt3jmAnyWCpZPBIk+x8rrb2xzIonKnOwvCJnXlT/6Ea7jXE+MWE4jdbHJyteWLs6C8pjSkFDpqSmcSzQaxDw=='
                              ];
            var sidkeyHash = utils.sha256(_td.SESSION_ID + _td.GROUP_KEY);
            for (var i = 0; i < tests.length; i++) {
                assert.notOk(ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_DATA_MESSAGE,
                                                       tests[i], atob(signatures[i]), _td.ED25519_PUB_KEY,
                                                       sidkeyHash),
                             'case ' + (i + 1));
            }
        });

    });

    describe("signMessage()/verifyMessageSignature()", function() {
        it('several round trips', function() {
            // Extend timeout, this test may take a bit longer.
            this.timeout(this.timeout() * 3);
            for (var i = 0; i < 5; i++) {
                var privKey = utils.randomString(32);
                var pubKey = utils.toPublicKey(privKey);
                var messageLength = Math.floor(1024 * Math.random());
                var message = _tu.cheapRandomString(messageLength);
                var signature = ns.signMessage(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                               message, privKey, pubKey);
                assert.ok(ns.verifyMessageSignature(ns.MESSAGE_TYPE.MPENC_GREET_MESSAGE,
                                                    message, signature, pubKey),
                          'iteration ' + (i + 1));
            }
        });
    });
});
