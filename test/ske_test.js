/**
 * @fileOverview
 * Test of the `mpenc.ske` module (Signature Key Exchange).
 */


"use strict";

/*
 * Created: 5 Feb 2014 Guy K. Kloss <gk@mega.co.nz>
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

//eabuse@nexgo.de
var RSA_PRIV_KEY = [[75021949, 120245708, 82706226, 16596609, 37674797,
                     261009791, 126581637, 200709099, 258471049, 113825880,
                     88027939, 220319392, 131853044, 135390860, 267228055,
                     237315027, 211313164, 54839697, 207660246, 201155346,
                     227695973, 146596047, 142916215, 98103316, 179900092,
                     249054037, 220438057, 256596528, 241826839, 63322446,
                     251511068, 58364369, 170132212, 133096195, 124672185,
                     8312302, 35400], // p
                    [128226797, 41208503, 207045529, 258570880, 23478973,
                     77404621, 158690389, 238844389, 145903872, 246313677,
                     253728308, 119494952, 195555019, 267612530, 78611566,
                     243360854, 132826684, 262537884, 119597852, 182907181,
                     30678391, 79728624, 137983547, 32175673, 139438215,
                     13886352, 203417847, 31483577, 219866889, 247380166,
                     68669996, 160814481, 39019433, 201943306, 81626508,
                     139781605, 47731], // q
                    [4785377, 8492163, 46352361, 214103223, 128434713,
                     33319427, 227333660, 55393381, 166852858, 190311278,
                     266421688, 178197776, 225843133, 62575637, 239940639,
                     156855074, 46489535, 230003976, 165629060, 232780285,
                     27515958, 240399426, 29901886, 3564677, 236070629,
                     3087466, 157736667, 117145646, 146679490, 131447613,
                     67842827, 140689194, 34183581, 109932386, 16816523,
                     52507178, 201828114, 221386889, 93069099, 159021540,
                     167588690, 136091483, 163072457, 205020932, 49104348,
                     262271640, 121715911, 214191306, 218845664, 212719951,
                     35202357, 132089769, 260900202, 14401018, 60968598,
                     132321672, 121097206, 89837308, 236860238, 65524891,
                     197578617, 28474670, 158355089, 180828899, 133890556,
                     114831284, 151264265, 46682207, 133668594, 136278850,
                     182380943, 147467667, 29746422, 1], // d
                    [75355783, 190006521, 55791789, 26515137, 173264457,
                     47953225, 101795657, 248544110, 210747547, 144990768,
                     238334760, 1290057, 33076917, 143776635, 180658031,
                     5206380, 79345545, 256436153, 106840740, 206602733,
                     246803249, 78668765, 129583422, 246220806, 123434098,
                     186736925, 150630366, 220873360, 145726505, 256243347,
                     11221355, 188285031, 37371460, 220704442, 39001519,
                     9996194, 23543] // u = (1/q) mod p (required for CRT supported computation)
                   ];

var RSA_PUB_KEY = [[230365881, 209576468, 15544222, 146241808, 252079570,
                    169310559, 52361850, 127099922, 7697172, 6914372,
                    240866415, 186381438, 265008541, 131249274, 5412023,
                    116822512, 70709639, 10120711, 102602468, 92538077,
                    145862676, 246410806, 2951361, 150478827, 225416106,
                    12000579, 243955194, 57120583, 219135684, 250266055,
                    78274356, 121632765, 44944666, 242161807, 33156870,
                    87720642, 248990925, 1826913, 79999139, 185294179,
                    144362878, 144835676, 208249376, 88043460, 9822520,
                    144028681, 242331074, 229487397, 166383609, 221149721,
                    20523056, 32680809, 225735686, 260562744, 256010236,
                    123473411, 149346591, 61685654, 30737, 192350750,
                    135348825, 161356467, 2560651, 40433759, 132363757,
                    203318185, 51857802, 175054024, 131105969, 235375907,
                    138707159, 209300719, 79084575, 6], // n = p * q
                   [17], // e
                   2047]; // size

var ED25519_PRIV_KEY = [108, 48, 210, 170, 135, 57, 232, 215, 218, 120, 133,
                        140, 227, 185, 49, 197, 178, 42, 136, 235, 87, 167,
                        187, 255, 3, 5, 111, 116, 151, 226, 89, 106, 204, 129,
                        223, 209, 50, 129, 251, 137, 228, 208, 36, 219, 223,
                        209, 26, 236, 181, 121, 189, 202, 223, 71, 5, 56, 226,
                        247, 47, 227, 156, 140, 153, 221];
var ED25519_PUB_KEY = [114, 247, 225, 72, 118, 8, 119, 84, 147, 80, 152, 202,
                       198, 41, 182, 156, 177, 201, 239, 63, 174, 55, 144, 55,
                       93, 86, 137, 103, 65, 133, 147, 229];

var SIGNATURE = [95, 246, 200, 16, 186, 217, 110, 4, 42, 25, 154, 34, 75, 141,
                 93, 104, 128, 186, 178, 212, 171, 141, 93, 73, 237, 3, 132,
                 191, 196, 160, 41, 125, 238, 96, 231, 235, 58, 72, 33, 112,
                 131, 178, 122, 171, 98, 196, 188, 161, 57, 143, 64, 204, 20,
                 90, 119, 49, 88, 30, 21, 94, 250, 203, 114, 148, 180, 128, 75,
                 75, 201, 219, 98, 92, 112, 203, 176, 210, 74, 59, 101, 175,
                 66, 199, 41, 165, 200, 101, 168, 98, 42, 2, 77, 7, 114, 10,
                 149, 48, 142, 94, 92, 135, 80, 45, 98, 124, 100, 94, 4, 197,
                 96, 143, 22, 207, 45, 127, 171, 51, 112, 35, 117, 28, 134,
                 232, 0, 5, 119, 203, 132, 70, 11, 234, 191, 223, 37, 221, 35,
                 228, 240, 102, 216, 238, 196, 254, 175, 148, 16, 250, 111,
                 150, 4, 216, 90, 187, 95, 14, 237, 102, 253, 201, 187, 166,
                 226, 194, 120, 247, 240, 60, 41, 244, 186, 117, 63, 211, 20,
                 130, 171, 200, 163, 239, 148, 235, 145, 216, 213, 99, 113,
                 150, 211, 233, 12, 22, 76, 0, 42, 255, 237, 244, 244, 45, 106,
                 157, 113, 254, 40, 135, 150, 163, 238, 203, 159, 126, 142,
                 186, 245, 219, 227, 111, 155, 174, 146, 218, 244, 80, 229, 12,
                 188, 247, 241, 210, 142, 249, 180, 33, 81, 232, 186, 216, 253,
                 95, 156, 244, 114, 97, 252, 221, 24, 50, 11, 72, 98, 204, 166,
                 54, 221, 206, 31, 67];

// // Generate with
// // openssl genrsa -out key.pem 2048
// var RSA_PRIV_KEY = "-----BEGIN RSA PRIVATE KEY----- \n\
// MIIEpAIBAAKCAQEA8XZXByd+rLMjFAWLL26sLhlipEZc7Q0/tiSjPgqIM2GBR/Jr \n\
//...
//rnqoAEd+1qb436CoRW/wkrqb0ITrxGhutjIM3eeseKROYLjMVBA1hA== \n\
//-----END RSA PRIVATE KEY-----";
//// Generate with
//// openssl req -new -x509 -days 3650 -key key.pem -out foo.pem -subj "/"
//var RSA_CERT = "-----BEGIN CERTIFICATE----- \n\
//MIIC0zCCAbugAwIBAgIJALuqKJZVQaMPMA0GCSqGSIb3DQEBBQUAMAAwHhcNMTQw \n\
//...
//gO6eW97yAMvNXYOjUwf9nt9gIkqMeuXSQ31WLhHX4cWGOQyisJb9zaCcAiCneLfc \n\
//Gp+M557ppA== \n\
//-----END CERTIFICATE-----";
//var RSA_MODULUS = "F1765707277EACB32314058B2F6EAC2E1962A4465CED0D3FB624A33E0A8\
//...
//7F36EC4982FD15B4409D18C954F8F6B20083BFB30BFFF8BAFB5DCFEB7495F19";
//var RSA_EXPONENT = 0x10001;

describe("module level", function() {
    var ns = mpenc.ske;
    
    describe('_binstring2mpi()', function() {
        it('convert message to MPI representation', function() {
            var messages = ['foo', 'The answer is 42!'];
            var expected = [[6713199],
                            [3420705, 33986354, 58156402, 33953511, 5531749]];
            for (var i = 0; i < messages.length; i++) {
                var result = ns._binstring2mpi(messages[i]);
                assert.deepEqual(result, expected[i]);
            }
        });
    });
    
    describe('_mpi2binstring()', function() {
        it('convert message from MPI representation', function() {
            var messages = [[6713199],
                            [3420705, 33986354, 58156402, 33953511, 5531749]];
            var expected = ['foo', 'The answer is 42!'];
            for (var i = 0; i < messages.length; i++) {
                var result = ns._mpi2binstring(messages[i]);
                assert.strictEqual(result, expected[i]);
            }
        });
    });
    
    describe('_pkcs1v15_encode()', function() {
        it('convert message to PKCS#1 v1.5 encoding', function() {
            var messages = ['foo', 'Klaatu barada nikto.'];
            for (var i = 0; i < messages.length; i++) {
                var result = ns._pkcs1v15_encode(messages[i], 256);
                assert.lengthOf(result, 256);
            }
        });

        it('encoding fail on too big message', function() {
            var message = ns._mpi2binstring(RSA_PUB_KEY[0]);
            assert.throws(function() { ns._pkcs1v15_encode(message, 256); },
                          'message too long for encoding scheme');
        });
    });
    
    describe('_pkcs1v15_decode()', function() {
        it('decoding fail on too small message', function() {
            assert.throws(function() { ns._pkcs1v15_decode('foo'); },
                          'message decoding error');
        });
    });
    
    describe('_pkcs1v15_encode()/_pkcs1v15_decode()', function() {
        it('roundtrip convert message with PKCS#1 v1.5 encoding', function() {
            var messages = ['foo', 'The answer is 42!'];
            for (var i = 0; i < messages.length; i++) {
                var result = ns._pkcs1v15_decode(ns._pkcs1v15_encode(messages[i], 256));
                assert.strictEqual(result, messages[i]);
            }
        });
    });
        
    describe('_smallrsaencrypt()/_smallrsadecrypt()', function() {
        it('RSA encryption and decryption round trip', function() {
            var messages = ['foo', 'The answer is 42!'];
            for (var i = 0; i < messages.length; i++) {
                var cipher = ns.smallrsaencrypt(messages[i], RSA_PUB_KEY);
                var clear = ns.smallrsadecrypt(cipher, RSA_PRIV_KEY);
                assert.strictEqual(clear, messages[i]);
            }
        });
    });
        
    describe('_smallrsaensign()/_smallrsadverify()', function() {
        it('RSA signing and verification round trip', function() {
            var messages = ['foo', 'The answer is 42!'];
            for (var i = 0; i < messages.length; i++) {
                var cipher = ns.smallrsasign(messages[i], RSA_PRIV_KEY);
                var clear = ns.smallrsaverify(cipher, RSA_PUB_KEY);
                assert.strictEqual(clear, messages[i]);
            }
        });
    });

    describe('_computeSid()', function() {
        it('compute SID', function() {
            var members = ['3', '1', '2', '4', '5'];
            var nonces = ['3333', '1111', '2222', '4444', '5555'];
            var EXPECTED = [182, 103, 240, 172, 49, 9, 66, 173,
                            157, 25, 191, 178, 191, 83, 149, 11,
                            164, 136, 60, 231, 106, 104, 76, 35,
                            187, 82, 125, 251, 225, 191, 124, 159];
            var sid = ns._computeSid(members, nonces);
            assert.deepEqual(sid, EXPECTED);
            // Now in changed order of items.
            members.sort();
            nonces.sort();
            sid = ns._computeSid(members, nonces);
            assert.deepEqual(sid, EXPECTED);
        });
    });
});

describe("SignatureKeyExchangeMember class", function() {
    var ns = mpenc.ske;
    
    describe('constructur', function() {
        it('simple constructor', function() {
            new ns.SignatureKeyExchangeMember();
        });
    });
    
    describe('#commit() method', function() {
        it('start commit chain', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var otherMembers = ['2', '3', '4', '5'];
            var spy = sinon.spy();
            participant.upflow = spy;
            participant.commit(otherMembers);
            sinon.assert.calledOnce(spy);
        });
        
        it('start commit chain without members', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            assert.throws(function() { participant.commit([]); },
                          'No members to add.');
        });
        
        it('start commit', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var otherMembers = ['2', '3', '4', '5'];
            var startMessage = participant.commit(otherMembers);
            assert.strictEqual(startMessage.source, '1');
            assert.strictEqual(startMessage.dest, '2');
            assert.strictEqual(startMessage.flow, 'upflow');
            assert.deepEqual(startMessage.members, ['1'].concat(otherMembers));
            assert.lengthOf(startMessage.nonces, 1);
            assert.lengthOf(startMessage.pubKeys, 1);
        });
    });
    
    describe('#_computeSessionSig() method', function() {
        it('sign something', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            participant.staticPrivKey = RSA_PRIV_KEY;
            participant.sessionId = [182, 103, 240, 172, 49, 9, 66, 173,
                                     157, 25, 191, 178, 191, 83, 149, 11,
                                     164, 136, 60, 231, 106, 104, 76, 35,
                                     187, 82, 125, 251, 225, 191, 124, 159];
            participant.ephemeralPubKey = ED25519_PRIV_KEY;
            var signature = participant._computeSessionSig();
            assert.strictEqual(keyBits(signature, 8), 2048);
        });
    });
    
    describe('#_verifySessionSig() method', function() {
        it('verify a signature', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            participant.members = ['1', '2', '3', '4', '5'];
            participant.staticPrivKey = RSA_PRIV_KEY;
            participant.sessionId = [182, 103, 240, 172, 49, 9, 66, 173,
                                     157, 25, 191, 178, 191, 83, 149, 11,
                                     164, 136, 60, 231, 106, 104, 76, 35,
                                     187, 82, 125, 251, 225, 191, 124, 159];
            participant.ephemeralPubKeys = [];
            for (var i = 0; i < 5; i++) {
                participant.ephemeralPubKeys.push(ED25519_PRIV_KEY);
            }
            participant.staticPubKeyDir['3'] = RSA_PUB_KEY;
            assert.strictEqual(participant._verifySessionSig('3', djbec._bytes2string(SIGNATURE)),
                               true);
            
            // TODO: check for asserts in _verifySessionSig code.
        });
    });
    
    describe('#upflow() method', function() {
        it('upflow duplicates in member list', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var members = ['3', '1', '2', '3', '4', '5', '6'];
            var startMessage = new ns.SignatureKeyExchangeMessage();
            startMessage.members = members;
            assert.throws(function() { participant.upflow(startMessage); },
                          'Duplicates in member list detected!');
        });
        
        it('upflow not in member list', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var members = ['2', '3', '4', '5', '6'];
            var startMessage = new ns.SignatureKeyExchangeMessage();
            startMessage.members = members;
            assert.throws(function() { participant.upflow(startMessage); },
                          'Not member of this key exchange!');
        });
        
        it('upflow, for initiator', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var members = ['1', '2', '3', '4', '5'];
            var startMessage = new ns.SignatureKeyExchangeMessage('1', '',
                                                                  'upflow',
                                                                  members);
            var message = participant.upflow(startMessage);
            assert.strictEqual(message.source, '1');
            assert.strictEqual(message.dest, '2');
            assert.deepEqual(message.members, members);
            assert.lengthOf(message.nonces, 1);
            assert.lengthOf(message.pubKeys, 1);
        });
        
        it('upflow, for all members', function() {
            var numMembers = 5;
            var members = [];
            var participants = [];
            for (var i = 1; i <= numMembers; i++) {
                members.push(i.toString());
                participants.push(new ns.SignatureKeyExchangeMember(i.toString()));
            }
            var message = new ns.SignatureKeyExchangeMessage('1', '',
                                                             'upflow',
                                                             members);
            for (var i = 0; i < numMembers - 1; i++) {
                message = participants[i].upflow(message);
                assert.deepEqual(participants[i].members, members);
                assert.strictEqual(keyBits(participants[i].ephemeralPrivKey, 8), 512);
                assert.strictEqual(keyBits(participants[i].ephemeralPubKey, 8), 256);
                assert.strictEqual(message.flow, 'upflow');
                assert.lengthOf(message.pubKeys, i + 1);
                assert.strictEqual(keyBits(message.pubKeys[i], 8), 256);
                assert.lengthOf(message.nonces, i + 1);
                assert.strictEqual(keyBits(message.nonces[i], 8), 256);
                assert.strictEqual(message.source, members[i]);
                assert.strictEqual(message.dest, members[i + 1]);
            }

            // The last member behaves differently.
            var lastid = numMembers - 1;
            participants[lastid].staticPrivKey = RSA_PRIV_KEY;
            message = participants[lastid].upflow(message);
            assert.deepEqual(participants[lastid].members, members);
            assert.deepEqual(participants[lastid].members, members);
            assert.strictEqual(keyBits(participants[lastid].ephemeralPrivKey, 8), 512);
            assert.strictEqual(keyBits(participants[lastid].ephemeralPubKey, 8), 256);
            assert.deepEqual(participants[lastid].authenticatedMembers,
                             [false, false, false, false, true]);
            assert.strictEqual(message.flow, 'downflow');
            assert.lengthOf(message.pubKeys, numMembers);
            assert.strictEqual(keyBits(message.pubKeys[lastid], 8), 256);
            assert.lengthOf(message.nonces, numMembers);
            assert.strictEqual(keyBits(message.nonces[lastid], 8), 256);
            assert.strictEqual(message.source, members[lastid]);
            assert.strictEqual(message.dest, '');
            assert.strictEqual(keyBits(participants[lastid].sessionId, 8), 256);
            assert.lengthOf(message.sessionSignature, 256);
        });
    });
    
    describe('#downflow() method', function() {
        it('downflow duplicates in member list', function() {
            var participant = new ns.SignatureKeyExchangeMember('1');
            var members = ['3', '1', '2', '3', '4', '5', '6'];
            var message = new ns.SignatureKeyExchangeMessage();
            message.members = members;
            assert.throws(function() { participant.downflow(message); },
                          'Duplicates in member list detected!');
        });
        
//        it('downflow, still unacknowledged', function() {
//            var members = ['1', '2', '3', '4', '5'];
//            var participant = new ns.SignatureKeyExchangeMember('3');
//            participant.staticPrivKey = RSA_PRIV_KEY;
//            participant.ephemeralPrivKey = ED25519_PRIV_KEY;
//            participant.ephemeralPubKey = ED25519_PUB_KEY;
//            var message = new ns.SignatureKeyExchangeMessage('1', '',
//                                                             'downflow',
//                                                             members);
//            for (var i = 0; i < 5; i++) {
//                // Nonces have the same format as the pub key.
//                message.nonces.push(ED25519_PUB_KEY);
//                message.pubKeys.push(ED25519_PUB_KEY);
//            }
//            message.sessionSignature = 'xyz';
//            var newMessage = participant.downflow(message);
//            assert.strictEqual(keyBits(participant.sessionId, 8), 256);
//            assert.strictEqual(participant.authenticatedMembers[0], true);
//            assert.strictEqual(participant.authenticatedMembers[2], true);
//            assert.ok(newMessage !== null);
//            
//            
//            // TODO:
//            // * test for failed auth
//            // * test for downflow past own broadcast
//        });
    });
});

//var bytes = djbec._string2bytes(message.sessionSignature);
//var hex = djbec._bytes2hex(bytes);
//assert.deepEqual(bytes, mpenc.utils.hex2bytearray(hex));
