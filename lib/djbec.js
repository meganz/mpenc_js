//  Ed25519 - digital signatures based on curve25519
//  Adapted from http://ed25519.cr.yp.to/python/ed25519.py by Ron Garret
//  December 2011
//
//  Requires jsbn and jsSHA
//  http://www-cs-students.stanford.edu/~tjw/jsbn/
//
//  Running under v8 highly recommended.  Anything else is pretty slow.

"use strict";

var djbec = {};

djbec._chr = function(n) {
    return String.fromCharCode(n);
};

djbec._ord = function(c) {
    return c.charCodeAt(0);
};

djbec._map = function(f, l) {
    var result = new Array(l.length);
    for (var i = 0; i < l.length; i++) {
        result[i] = f(l[i]);
    }
    return result;
};

djbec._bytes2string = function(bytes) {
    return djbec._map(djbec._chr, bytes).join('');
};

djbec._string2bytes = function(s) {
    return djbec._map(djbec._ord, s);
};

djbec._bi2bytes = function(n, cnt) {
    if (cnt == undefined) {
        cnt = (n.bitLength() >> 3) + 1;
    }
    var bytes = new Array(cnt);
    for (var i = 0; i < cnt; i++) {
        bytes[i] = n[0] & 255; // n.and(xff);
        n = n.shiftRight(8);
    }
    return bytes;
};

djbec._bytes2bi = function(bytes) {
    var n = djbec._bi('0');
    for (var i = bytes.length - 1; i > -1; i--) {
        n = n.shiftLeft(8).or(djbec._bi('' + bytes[i]));
    }
    return n;
};

djbec._hex2bi = function(s) {
    return new BigInteger(s, 16);
};

// BigInteger construction done right
djbec._bi = function(s, base) {
    if (base != undefined) {
        if (base == 256) {
            return djbec._bytes2bi(djbec._string2bytes(s));
        }
        return new BigInteger(s, base);
    } else if (typeof s == 'string') {
        return new BigInteger(s, 10);
    } else if (s instanceof Array) {
        return djbec._bytes2bi(s);
    } else if (typeof s == 'number') {
        return new BigInteger(s.toString(), 10);
    } else {
        throw "Can't convert " + s + " to BigInteger";
    }
};

djbec._sha512 = function(s) { // Requires jsSHA
    var shaObj = new jsSHA(s, "ASCII");
    return djbec._bi2bytes(djbec._hex2bi(shaObj.getHash("SHA-512", "HEX")), 64).reverse();
};

djbec._inthash = function(s) {
    return djbec._bytes2bi(djbec._sha512(s));
};

djbec._stringhash = function(s) {
    return djbec._bytes2string(djbec._sha512(s));
};

djbec._zero = BigInteger.ZERO;
djbec._one = BigInteger.ONE;
djbec._two = djbec._bi('2');

BigInteger.prototype.times = BigInteger.prototype.multiply;
BigInteger.prototype.plus = BigInteger.prototype.add;
BigInteger.prototype.minus = BigInteger.prototype.subtract;
BigInteger.prototype.square = function() {
    return this.times(this);
};

djbec._xff = djbec._bi('255');
djbec._b = djbec._bi('256');
djbec._q = djbec._two.pow(djbec._bi('255')).minus(djbec._bi('19'));
djbec._l = djbec._two.pow(252).add(djbec._bi('27742317777372353535851937790883648493'));

djbec._k1 = djbec._two.pow(djbec._b.minus(djbec._two));
djbec._k2 = djbec._two.pow(251).minus(djbec._one).shiftLeft(3);

djbec._inv = function(n) {
    return n.mod(djbec._q).modInverse(djbec._q);
};

djbec._d = djbec._bi('-121665').times(djbec._inv(djbec._bi('121666'))).mod(djbec._q);
djbec._i = djbec._two.modPow(djbec._q.minus(djbec._one).divide(djbec._bi('4')), djbec._q);

djbec._xrecover = function(y) {
    var ysquared = y.times(y);
    var xx = ysquared.minus(djbec._one).times(djbec._inv(djbec._one.add(djbec._d.times(ysquared))));
    var x = xx.modPow(djbec._q.add(djbec._bi('3')).divide(djbec._bi('8')), djbec._q);
    if (!(x.times(x).minus(xx).mod(djbec._q).equals(djbec._zero))) {
        x = x.times(djbec._i).mod(djbec._q);
    }
    if (!(x.mod(djbec._two).equals(djbec._zero))) {
        x = djbec._q.minus(x);
    }
    return x;
};

djbec._by = djbec._inv(djbec._bi('5')).times(djbec._bi('4')).mod(djbec._q);
djbec._bx = djbec._xrecover(djbec._by);
djbec._bp = [djbec._bx, djbec._by];

// Simple but slow version

djbec._edwards = function(p1, p2) {
    var x1 = p1[0];
    var y1 = p1[1];
    var x2 = p2[0];
    var y2 = p2[1];
    var k = djbec._d.times(x1).times(x2).times(y1).times(y2);
    var x3 = x1.times(y2).add(x2.times(y1)).times(djbec._inv(djbec._one.plus(k)));
    var y3 = y1.times(y2).add(x1.times(x2)).times(djbec._inv(djbec._one.minus(k)));
    return [x3.mod(djbec._q), y3.mod(djbec._q)];
};

// Based on:
// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html

djbec._xpt_add = function(pt1, pt2) {
    var x1 = pt1[0];
    var y1 = pt1[1];
    var z1 = pt1[2];
    var t1 = pt1[3];
    var x2 = pt2[0];
    var y2 = pt2[1];
    var z2 = pt2[2];
    var t2 = pt2[3];
    var A = y1.minus(x1).times(y2.plus(x2)).mod(djbec._q);
    var B = y1.plus(x1).times(y2.minus(x2)).mod(djbec._q);
    var C = z1.times(djbec._two).times(t2).mod(djbec._q);
    var D = t1.times(djbec._two).times(z2).mod(djbec._q);
    var E = D.plus(C);
    var F = B.minus(A);
    var G = B.plus(A);
    var H = D.minus(C);
    return [E.times(F).mod(djbec._q), G.times(H).mod(djbec._q), F.times(G).mod(djbec._q),
            E.times(H).mod(djbec._q)];
};

djbec._xpt_double = function(pt1) {
    var x1 = pt1[0];
    var y1 = pt1[1];
    var z1 = pt1[2];
    var A = x1.times(x1);
    var B = y1.times(y1);
    var C = djbec._two.times(z1).times(z1);
    var D = djbec._zero.minus(A).mod(djbec._q);
    var J = x1.plus(y1);
    var E = J.times(J).minus(A).minus(B);
    var G = D.plus(B);
    var F = G.minus(C);
    var H = D.minus(B);
    return [E.times(F).mod(djbec._q), G.times(H).mod(djbec._q), F.times(G).mod(djbec._q),
            E.times(H).mod(djbec._q)];
};

djbec._xpt_mult = function(pt, n) {
    if (n.equals(djbec._zero)) {
        return [djbec._zero, djbec._one, djbec._one, djbec._zero];
    }
    var _ = djbec._xpt_mult(pt, n.shiftRight(1));
    _ = djbec._xpt_double(_);
    if (n.testBit(0)) {
        return djbec._xpt_add(_, pt);
    } else {
        return _;
    }
};

djbec._pt_xform = function(pt) {
    var x = pt[0];
    var y = pt[1];
    return [x, y, djbec._one, x.times(y).mod(djbec._q)];
};

djbec._pt_unxform = function(pt) {
    var x = pt[0];
    var y = pt[1];
    var z = pt[2];
    var invz = djbec._inv(z);
    return [x.times(invz).mod(djbec._q), y.times(invz).mod(djbec._q)];
};

djbec._scalarmult = function(pt, n) {
    return djbec._pt_unxform(djbec._xpt_mult(djbec._pt_xform(pt), n));
};

djbec._encodeint = function(n) {
    return djbec._bi2bytes(n, 32);
};

djbec._encodepoint = function(p) {
    var x = p[0];
    var y = p[1];
    return djbec._encodeint(y.add(x.and(djbec._one).shiftLeft(255)));
};


/**
 * Derive the public key from the given secret key.
 * 
 * @param sk
 *     Secret key given as a array of bytes.
 * @returns {Array}
 */
djbec.publickey = function(sk) {
    var h = djbec._bytes2bi(sk);
    var a = djbec._k1.add(djbec._k2.and(h));
    return djbec._encodepoint(djbec._scalarmult(djbec._bp, a));
};


/**
 * Generates a signature for the given message.
 * 
 * @param m
 *     Message to sign (as array of bytes).
 * @param sk
 *     Private key (as array of bytes).
 * @param pk
 *     Public key (corresponding to private key, as array of bytes).
 * @returns
 *     Signature.
 */
djbec.signature = function(m, sk, pk) {
    var hi = djbec._bytes2bi(sk);
    var hs = djbec._bytes2string(sk);
    var a = djbec._k1.add(djbec._k2.and(hi));
    var r = djbec._inthash(hs.slice(32, 64) + m);
    var rp = djbec._scalarmult(djbec._bp, r);
    var s0 = djbec._inthash(djbec._bytes2string(djbec._encodepoint(rp)) + djbec._bytes2string(pk) + m);
    var s = r.add(a.times(s0)).mod(djbec._l);
    return djbec._encodepoint(rp).concat(djbec._encodeint(s));
};

djbec._isoncurve = function(p) {
    var x = p[0];
    var y = p[1];
    var v = djbec._d.times(x).times(x).times(y).times(y).mod(djbec._q);
    return y.times(y).minus(x.times(x)).minus(djbec._one).minus(v).mod(djbec._q)
            .equals(djbec._zero);
};

djbec._decodeint = function(v) {
    return djbec._bytes2bi(v, 32);
};

djbec._decodepoint = function(v) {
    var y = djbec._bytes2bi(v, 32).and(djbec._two.pow(djbec._xff).minus(djbec._one));
    var x = djbec._xrecover(y);
    if ((x.testBit(0) ? 1 : 0) != v[31] >> 7) {
        x = djbec._q.minus(x);
    }
    var p = [x, y];
    if (!djbec._isoncurve(p)) {
        throw ('Point is not on curve');
    }
    return p;
};


/**
 * Checks the signature of a message for validity against a given public key.
 * 
 * @param sig
 *     Signature.
 * @param msg
 *     Message to verify signature (as array of bytes).
 * @param pk
 *     Public key to verify against (as array of bytes).
 * @returns
 *     True if the signature is verified successfully.
 */
djbec.checksig = function(sig, msg, pk) {
    var r = djbec._decodepoint(sig.slice(0, 32));
    var a = djbec._decodepoint(pk);
    var s = djbec._decodeint(sig.slice(32, 64));
    var h = djbec._inthash(djbec._bytes2string(djbec._encodepoint(r).concat(pk)) + msg);
    var v1 = djbec._scalarmult(djbec._bp, s);
    var v2 = djbec._edwards(r, djbec._scalarmult(a, h));
    return v1[0].equals(v2[0]) && v1[1].equals(v2[1]);
};

djbec._sig_test = function() {
    var msg = 'Hello, World!';              // The message.
    var sk = mpenc.utils._newKey08(512);    // New secret signature key (512 bit).
    var pk = djbec.publickey(sk);           // Pub key for verification (256 bit).
    var sig = djbec.signature(msg, sk, pk); // Signature (512 bit).
    var chk = djbec.checksig(sig, msg, pk); // True if signature verifies.
};
