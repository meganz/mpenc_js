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

//// Generate with
//// openssl genrsa -out key.pem 2048
//var RSA_PRIV_KEY = "-----BEGIN RSA PRIVATE KEY----- \n\
//MIIEpAIBAAKCAQEA8XZXByd+rLMjFAWLL26sLhlipEZc7Q0/tiSjPgqIM2GBR/Jr \n\
//BJzNnbPyz0KJjLUUGAxglqCeYjsDfYiaiP11HJu1FGGcH9/K9FN4Gf/5PhBp0T18 \n\
//NFd5pfL5X/NGQ2RFuPKdRx21rZb087DwkjJccz3DZ3k7AzzviV/OM2PuIof99a+9 \n\
//fGKrZo5FjGjrUIAiANDjeV9FSp25P0saAiZbFh3jkULzetMSjdUbO7Yiw1v9vB78 \n\
//UBOfvzs97h44OnW73cNPyzEjGzb58uwDoZzB/aF7rGOmX8GbHiJnm3LirV9n827E \n\
//mC/RW0QJ0YyVT49rIAg7+zC//4uvtdz+t0lfGQIDAQABAoIBAQCux2grR41L2McV \n\
//YQXkqYl8POfH3R66gBKT92UqLVl1R6jauUB5sD6tXmntWE5USWZoGd14an76v5jB \n\
//LzYc3sn8kUC7pgPqloVD4X9X4o85O4w85vKWuJLXak7UAzXi5hwJyaPKrFirdE+O \n\
//bY9VY5rD1/svVPNAXsVMfMq3LChdWQauLNxgm2zU1haJ8FNz9ajw5pDZ5sHcS7T2 \n\
//QkWtQPa+eN6NDeLSTboi+OlfWcB4fLc1BpWEUv/GRwP5upkTfZY0q3CMqsGLUjZJ \n\
//B8/ODYRHt4q+Wu8FVYW6rtpi8nBOu1zjdFktpUEVoLj33lVg/LZFgyO+Ev2ByE0V \n\
//7mLyH7cBAoGBAPi2juKo0cgd60TC6U6HGwtfuwbskkpx423SxK41K0OUBUdBLcfg \n\
//xuq4OEmqXA9xgp7xcz6RFu9MP/6p2H4O7LUr+LzlEWaiUFLsVqbDFt8NnGJQULAT \n\
//LpLl3uPNmtNmVL4l2YIs26buzaNxiQgE/oqPsLbgM162Hc99m3gAudYRAoGBAPiJ \n\
//Zc76giBAjv8EU5+R29QZEwCxf8dQoT98rPPcOlmNxrqnB25z6aifumPCDgSWAC8F \n\
//6jrdY2Uus09ot6SzxayBqsVd2BSCuVWpPqhmTZPRZqplo3DoE9SYeD5tcmo2mws0 \n\
//rqbsjSurwP+GaJFoNsJlZknxN33y71KlcO9vaNCJAoGBAI/FF/u2Eu5XPTTWZv9Z \n\
//4ixE/lwWTMpz40AM4lzBp2y9GAAEkW5FZTcxnngW3nie6R7v++pi/Jr/vM59aAQW \n\
//pIZmELdAwzpNAZmtvLlRdNsjhw7d1oaxz+5iquGMbL9fHAV+46j4PVDWIlEkxE26 \n\
//dVmrjj9ogslxBPJ4bXKFGOfBAoGAcD6tSiL87c/6RNYRZjmbjFieqmt/h+a0TFXk \n\
//TmYhvBw5qkaRJqMW3d71cORNLGkKQDJtrJQbtbC3rp9egPXnypbtJyHQ2sKHLVa4 \n\
//Q5mgY6fotAAfJnjJq/QIKjmHuMxcjV0Hm7+tqhFxonVzeGgWgwkEf1R/eVRkHXE2 \n\
//Zgxsy/ECgYBHzFzJCgodwi869ikzQfoixJgV1GfNXIQLkBjLHFdKMv9Ae+DLNKx1 \n\
//SIwLhpbOxkIHPZxTFNbjl2eqCj+PlX4+/hrOKEY/T4bvMJnQ9q33VG2DdMPejG45 \n\
//rnqoAEd+1qb436CoRW/wkrqb0ITrxGhutjIM3eeseKROYLjMVBA1hA== \n\
//-----END RSA PRIVATE KEY-----";
//// Generate with
//// openssl req -new -x509 -days 3650 -key key.pem -out foo.pem -subj "/"
//var RSA_CERT = "-----BEGIN CERTIFICATE----- \n\
//MIIC0zCCAbugAwIBAgIJALuqKJZVQaMPMA0GCSqGSIb3DQEBBQUAMAAwHhcNMTQw \n\
//MjE5MDQyNDMwWhcNMjQwMjE3MDQyNDMwWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOC \n\
//AQ8AMIIBCgKCAQEA8XZXByd+rLMjFAWLL26sLhlipEZc7Q0/tiSjPgqIM2GBR/Jr \n\
//BJzNnbPyz0KJjLUUGAxglqCeYjsDfYiaiP11HJu1FGGcH9/K9FN4Gf/5PhBp0T18 \n\
//NFd5pfL5X/NGQ2RFuPKdRx21rZb087DwkjJccz3DZ3k7AzzviV/OM2PuIof99a+9 \n\
//fGKrZo5FjGjrUIAiANDjeV9FSp25P0saAiZbFh3jkULzetMSjdUbO7Yiw1v9vB78 \n\
//UBOfvzs97h44OnW73cNPyzEjGzb58uwDoZzB/aF7rGOmX8GbHiJnm3LirV9n827E \n\
//mC/RW0QJ0YyVT49rIAg7+zC//4uvtdz+t0lfGQIDAQABo1AwTjAdBgNVHQ4EFgQU \n\
//fnnyXtpnX7tQtrTWyZkNfij8lpYwHwYDVR0jBBgwFoAUfnnyXtpnX7tQtrTWyZkN \n\
//fij8lpYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA6Ostq4KGKevY \n\
//nr3ZlPfUG4ZYjTl1SAt4rrjbNvpRcIvWlX/ZnDeBQyJU9krvnfNcKlGyUzErR712 \n\
//WjW4e0tPXLBmnIz9WjLfpPBiTLRGPxuzQvz/dQedUoVU/MvGp4uJSLFSWvpzxvO+ \n\
//qiOYWzRzs5tkKDEN1jitsbctTBmHMTO9D6CRgBzbOLTySnG+h2H+uMbxP6rxZkgg \n\
//PO6hrL6GmKeYQiVAKQmf6zdYiDjMxfEN14DNdWFfdtXhjJzXsszAbWDbsaRuY1RF \n\
//gO6eW97yAMvNXYOjUwf9nt9gIkqMeuXSQ31WLhHX4cWGOQyisJb9zaCcAiCneLfc \n\
//Gp+M557ppA== \n\
//-----END CERTIFICATE-----";
//var RSA_MODULUS = "F1765707277EACB32314058B2F6EAC2E1962A4465CED0D3FB624A33E0A8\
//833618147F26B049CCD9DB3F2CF42898CB514180C6096A09E623B037D889A88FD751C9BB514619\
//C1FDFCAF4537819FFF93E1069D13D7C345779A5F2F95FF346436445B8F29D471DB5AD96F4F3B0F\
//092325C733DC367793B033CEF895FCE3363EE2287FDF5AFBD7C62AB668E458C68EB50802200D0E\
//3795F454A9DB93F4B1A02265B161DE39142F37AD3128DD51B3BB622C35BFDBC1EFC50139FBF3B3\
//DEE1E383A75BBDDC34FCB31231B36F9F2EC03A19CC1FDA17BAC63A65FC19B1E22679B72E2AD5F6\
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
            var messages = ['foo', 'The answer is 42!'];
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
            assert.strictEqual(startMessage.msgType, 'upflow');
            assert.deepEqual(startMessage.members, ['1'].concat(otherMembers));
            assert.lengthOf(startMessage.nonces, 1);
            assert.lengthOf(startMessage.pubKeys, 1);
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
        
        it('TODO: remove this', function() {
        });
    });
});
