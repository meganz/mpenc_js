//  Ed25519 - digital signatures based on curve25519
//  Adapted from http://ed25519.cr.yp.to/python/ed25519.py by Ron Garret
//  December 2011
//
//  Requires jsbn and jsSHA
//  http://www-cs-students.stanford.edu/~tjw/jsbn/
//
//  Running under v8 highly recommended.  Anything else is pretty slow.


function _chr(n) {
    return String.fromCharCode(n);
}
function _ord(c) {
    return c.charCodeAt(0);
}

function _map(f, l) {
    var result = new Array(l.length);
    for (var i = 0; i < l.length; i++) {
        result[i] = f(l[i]);
    }
    return result;
}

function _bytes2string(bytes) {
    return _map(_chr, bytes).join('');
}

function _string2bytes(s) {
    return _map(_ord, s);
}

function _bi2bytes(n, cnt) {
    if (cnt == undefined) {
        cnt = (n.bitLength() >> 3) + 1;
    }
    var bytes = new Array(cnt);
    for (var i = 0; i < cnt; i++) {
        bytes[i] = n[0] & 255; // n.and(xff);
        n = n.shiftRight(8);
    }
    return bytes;
}

function _bytes2bi(bytes) {
    var n = _bi('0');
    for (var i = bytes.length - 1; i > -1; i--) {
        n = n.shiftLeft(8).or(_bi('' + bytes[i]));
    }
    return n;
}

function _hex2bi(s) {
    return new BigInteger(s, 16);
}

// BigInteger construction done right
function _bi(s, base) {
    if (base != undefined) {
        if (base == 256) {
            return _bytes2bi(_string2bytes(s));
        }
        return new BigInteger(s, base);
    } else if (typeof s == 'string') {
        return new BigInteger(s, 10);
    } else if (s instanceof Array) {
        return _bytes2bi(s);
    } else if (typeof s == 'number') {
        return new BigInteger(s.toString(), 10);
    } else {
        throw "Can't convert " + s + " to BigInteger";
    }
}

function _sha512(s) { // Requires jsSHA
    var shaObj = new jsSHA(s, "ASCII");
    return _bi2bytes(_hex2bi(shaObj.getHash("SHA-512", "HEX")), 64).reverse();
}

function _inthash(s) {
    return _bytes2bi(_sha512(s));
}

function _stringhash(s) {
    return _bytes2string(_sha512(s));
}

var _zero = BigInteger.ZERO;
var _one = BigInteger.ONE;
var _two = _bi('2');

BigInteger.prototype.times = BigInteger.prototype.multiply;
BigInteger.prototype.plus = BigInteger.prototype.add;
BigInteger.prototype.minus = BigInteger.prototype.subtract;
BigInteger.prototype.square = function() {
    return this.times(this);
};

var _xff = _bi('255');
var _b = _bi('256');
var _q = _two.pow(_bi('255')).minus(_bi('19'));
var _l = _two.pow(252).add(_bi('27742317777372353535851937790883648493'));

var _k1 = _two.pow(_b.minus(_two));
var _k2 = _two.pow(251).minus(_one).shiftLeft(3);

function _inv(n) {
    return n.mod(_q).modInverse(_q);
}

var _d = _bi('-121665').times(_inv(_bi('121666'))).mod(_q);
var _i = _two.modPow(_q.minus(_one).divide(_bi('4')), _q);

function _xrecover(y) {
    var ysquared = y.times(y);
    var xx = ysquared.minus(_one).times(_inv(_one.add(_d.times(ysquared))));
    var x = xx.modPow(_q.add(_bi('3')).divide(_bi('8')), _q);
    if (!(x.times(x).minus(xx).mod(_q).equals(_zero))) {
        x = x.times(_i).mod(_q);
    }
    if (!(x.mod(_two).equals(_zero))) {
        x = _q.minus(x);
    }
    return x;
}

var _by = _inv(_bi('5')).times(_bi('4')).mod(_q);
var _bx = _xrecover(_by);
var _bp = [_bx, _by];

// Simple but slow version

function _edwards(p1, p2) {
    var x1 = p1[0];
    var y1 = p1[1];
    var x2 = p2[0];
    var y2 = p2[1];
    var k = _d.times(x1).times(x2).times(y1).times(y2);
    var x3 = x1.times(y2).add(x2.times(y1)).times(_inv(_one.plus(k)));
    var y3 = y1.times(y2).add(x1.times(x2)).times(_inv(_one.minus(k)));
    return [x3.mod(_q), y3.mod(_q)];
}

function _slow_scalarmult(p, e) {
    if (e.equals(_zero)) {
        return [_zero, _one];
    }
    var _ = _scalarmult(p, e.divide(_two));
    _ = _edwards(_, _);
    if (e.testBit(0)) {
        return _edwards(_, p);
    } else {
        return _;
    }
}

// Faster (!) version based on:
// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html

function _xpt_add(pt1, pt2) {
    var x1 = pt1[0];
    var y1 = pt1[1];
    var z1 = pt1[2];
    var t1 = pt1[3];
    var x2 = pt2[0];
    var y2 = pt2[1];
    var z2 = pt2[2];
    var t2 = pt2[3];
    var A = y1.minus(x1).times(y2.plus(x2)).mod(_q);
    var B = y1.plus(x1).times(y2.minus(x2)).mod(_q);
    var C = z1.times(_two).times(t2).mod(_q);
    var D = t1.times(_two).times(z2).mod(_q);
    var E = D.plus(C);
    var F = B.minus(A);
    var G = B.plus(A);
    var H = D.minus(C);
    return [E.times(F).mod(_q), G.times(H).mod(_q), F.times(G).mod(_q),
            E.times(H).mod(_q)];
}

function _xpt_double(pt1) {
    var x1 = pt1[0];
    var y1 = pt1[1];
    var z1 = pt1[2];
    var A = x1.times(x1);
    var B = y1.times(y1);
    var C = _two.times(z1).times(z1);
    var D = _zero.minus(A).mod(_q);
    var J = x1.plus(y1);
    var E = J.times(J).minus(A).minus(B);
    var G = D.plus(B);
    var F = G.minus(C);
    var H = D.minus(B);
    return [E.times(F).mod(_q), G.times(H).mod(_q), F.times(G).mod(_q),
            E.times(H).mod(_q)];
}

function _xpt_mult(pt, n) {
    if (n.equals(_zero)) {
        return [_zero, _one, _one, _zero];
    }
    var _ = _xpt_mult(pt, n.shiftRight(1));
    _ = _xpt_double(_);
    if (n.testBit(0)) {
        return _xpt_add(_, pt);
    } else {
        return _;
    }
}

function _pt_xform(pt) {
    var x = pt[0];
    var y = pt[1];
    return [x, y, _one, x.times(y).mod(_q)];
}

function _pt_unxform(pt) {
    var x = pt[0];
    var y = pt[1];
    var z = pt[2];
    var invz = _inv(z);
    return [x.times(invz).mod(_q), y.times(invz).mod(_q)];
}

function _scalarmult(pt, n) {
    return _pt_unxform(_xpt_mult(_pt_xform(pt), n));
}

function _encodeint(n) {
    return _bi2bytes(n, 32);
}

function _encodepoint(p) {
    var x = p[0];
    var y = p[1];
    return _encodeint(y.add(x.and(_one).shiftLeft(255)));
}


/**
 * Derive the public key from the given secret key.
 * 
 * @param sk
 *     Secret key given as a array of bytes.
 * @returns {Array}
 */
function ed25519publickey(sk) {
    var h = _bytes2bi(sk);
    var a = _k1.add(_k2.and(h));
    return _encodepoint(_scalarmult(_bp, a));
}


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
function ed25519signature(m, sk, pk) {
    var hi = _bytes2bi(sk);
    var hs = _bytes2string(sk);
    var a = _k1.add(_k2.and(hi));
    var r = _inthash(hs.slice(32, 64) + m);
    var rp = _scalarmult(_bp, r);
    var s0 = _inthash(_bytes2string(_encodepoint(rp)) + _bytes2string(pk) + m);
    var s = r.add(a.times(s0)).mod(_l);
    return _encodepoint(rp).concat(_encodeint(s));
}

function _isoncurve(p) {
    var x = p[0];
    var y = p[1];
    var v = _d.times(x).times(x).times(y).times(y).mod(_q);
    return y.times(y).minus(x.times(x)).minus(_one).minus(v).mod(_q)
            .equals(_zero);
}

function _decodeint(v) {
    return _bytes2bi(v, 32);
}

function _decodepoint(v) {
    var y = _bytes2bi(v, 32).and(_two.pow(_xff).minus(_one));
    var x = _xrecover(y);
    if ((x.testBit(0) ? 1 : 0) != v[31] >> 7) {
        x = _q.minus(x);
    }
    var p = [x, y];
    if (!_isoncurve(p)) {
        throw ('Point is not on curve');
    }
    return p;
}


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
function ed25519checksig(sig, msg, pk) {
    var r = _decodepoint(sig.slice(0, 32));
    var a = _decodepoint(pk);
    var s = _decodeint(sig.slice(32, 64));
    var h = _inthash(_bytes2string(_encodepoint(r).concat(pk)) + msg);
    var v1 = _scalarmult(_bp, s);
    var v2 = _edwards(r, _scalarmult(a, h));
    return v1[0].equals(v2[0]) && v1[1].equals(v2[1]);
}

function _sig_test() {
    var msg = 'Hello, World!';               // The message.
    var sk = _newKey08(512);                 // New secret signature key (512 bit).
    var pk = ed25519publickey(sk);           // Pub key for verification (256 bit).
    var sig = ed25519signature(msg, sk, pk); // Signature (512 bit).
    var chk = ed25519checksig(sig, msg, pk); // True if signature verifies.
}
