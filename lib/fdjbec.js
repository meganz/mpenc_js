
//  Ed25519 - digital signatures based on curve25519
//  Adapted from http://ed25519.cr.yp.to/python/ed25519.py by Ron Garret
//  October 2012
//
//  Requires jsbn, jsSHA, and Michele Bini's curve25519 code
//  http://www-cs-students.stanford.edu/~tjw/jsbn/
//  https://github.com/Caligatio/jsSHA/
//  http://savannah.gnu.org/task/?6432
//
//  This code is a faster but more complicated version of the curve25519
//  public-key encryption algorithms.  It uses two different representations
//  for big integers, the jsbn BigInteger class, which can represent
//  arbitrary-length numbers, and a special fixed-length representation
//  optimized for 256-bit integers.  The reason both are needed is that
//  the Ed25519 algorithm requires some 512-bit numbers.

"use strict";

load('curve25519.js')

function bi255(_) {
  if (!(this instanceof bi255)) return new bi255(_);
  if (typeof _ === 'undefined') { return bi255(0); }
  var c = _.constructor;
  if ((c === Array) && (_.length==16)) this.n = _;
  else if ((c === Array) && (_.length==32)) this.n = bytes2bi255(_).n;
  else if (c === String) this.n = c255lhexdecode(_);
  else if (c === Number) this.n = [_&0xffff,_>>16,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
  else if (_ instanceof bi255) this.n = _.n.slice(0);  // Copy constructor
  else throw "Bad argument for bignum: " + _;
}

bi255.prototype = {
  'toString' : function() { return c255lhexencode(this.n); },
  'toSource' : function() { return '_' + c255lhexencode(this.n); },
  'plus' : function (n1) { return bi255(c255lbigintadd(this.n, n1.n)); },
  'minus' : function (n1) {
    return bi255(c255lbigintsub(this.n, n1.n)).modq(); },
  'times' : function (n1) { return bi255(c255lmulmodp(this.n, n1.n)); },
  'divide' : function (n1) { return this.times(n1.inv()); },
  'sqr' : function () { return bi255(c255lsqrmodp(this.n)); },
  'cmp' : function (n1) { return c255lbigintcmp(this.n, n1.n); },
  'equals' : function (n1) { return this.cmp(n1)===0; },
  'isOdd' : function () { return (this.n[0]&1)===1; },
  'shiftLeft' : function (cnt) { shiftL(this.n, cnt); return this; },
  'shiftRight' : function (cnt) { shiftR(this.n, cnt); return this; },
  'inv' : function () { return bi255(c255linvmodp(this.n)); },
  'pow' : function (e) { return bi255(pow(this.n, e.n)); },
  'modq' : function() { return modq(this); },
  'bytes' : function () { return bi255_bytes(this); }
};

function shiftL(n, cnt) {
  var lastcarry=0;
  for (var i=0; i<16; i++) {
    var carry = n[i]>>(16-cnt);
    n[i] = (n[i]<<cnt)&0xffff|lastcarry;
    lastcarry = carry;
  }
  return n;
}

function shiftR(n, cnt) {
  var lastcarry=0;
  for (var i=15; i>=0; i--) {
    var carry = n[i]<<(16-cnt)&0xffff;
    n[i] = (n[i]>>cnt)|lastcarry;
    lastcarry = carry;
  }
  return n;
}

function bi255_bytes(n) {
  n = bi255(n);          // Make a copy because shiftRight is destructive
  var a = new Array(32);
  for (var i=31; i>=0; i--) {
    a[i]=n.n[0] & 0xff;
    n.shiftRight(8);
  }
  return a;
}

function bytes2bi255(a) {
  var n = bi255(0);
  for (var i = 0; i<32; i++) {
    n.shiftLeft(8);
    n = n.plus(bi255(a[i]));
  }
  return n;
}

function pow(n, e) {
  var result = c255lone();
  for (var i=0; i<256; i++) {
    if (c255lgetbit(e,i)===1) {
      result = c255lmulmodp(result, n);
    }
    n = c255lsqrmodp(n);
  }
  return result;
}

function modq(n) {
  c255lreduce(n.n);
  if (n.cmp(q)>=0) return modq(n.minus(q));
  if (n.cmp(zero)===-1) return modq(n.plus(q));
  else return n
}

var zero = bi255(0);
var one = bi255(1);
var two = bi255(2);
var q = bi255(c255lprime);
var negone = q.minus(one);
var d = q.minus(bi255(121665)).divide(bi255(121666));
var i = two.pow(q.minus(one).divide(bi255(4)));
var l = two.pow(bi255(252)).plus(bi255('14def9dea2f79cd65812631a5cf5d3ed'));

//////////////////////////////////////////////////////////////

function isoncurve(p) {
  var x = p[0];
  var y = p[1];
  var xsqr = x.sqr();
  var ysqr = y.sqr();
  var v = d.times(xsqr).times(ysqr);
  return ysqr.minus(xsqr).minus(one).minus(v).modq().equals(zero);
}

function xrecover(y) {
  var ysquared = y.sqr();
  var xx = ysquared.minus(one).divide(one.plus(d.times(ysquared)));
  var x = xx.pow(q.plus(bi255('3')).divide(bi255('8')));
  if (!(x.times(x).minus(xx).equals(zero))) {
    x = x.times(i);
  }
  if (x.isOdd()) {
    x = q.minus(x);
  }
  return x;
}

function xpt_add(pt1, pt2) {
  var x1 = pt1[0];
  var y1 = pt1[1];
  var z1 = pt1[2];
  var t1 = pt1[3];
  var x2 = pt2[0];
  var y2 = pt2[1];
  var z2 = pt2[2];
  var t2 = pt2[3];
  var A = y1.minus(x1).times(y2.plus(x2));
  var B = y1.plus(x1).times(y2.minus(x2));
  var C = z1.times(two).times(t2);
  var D = t1.times(two).times(z2);
  var E = D.plus(C);
  var F = B.minus(A);
  var G = B.plus(A);
  var H = D.minus(C);
  return [E.times(F), G.times(H), F.times(G), E.times(H)];
}

function xpt_double(pt1) {
  var x1 = pt1[0];
  var y1 = pt1[1];
  var z1 = pt1[2];
  var A = x1.times(x1);
  var B = y1.times(y1);
  var C = two.times(z1).times(z1);
  var D = q.minus(A);
  var J = x1.plus(y1);
  var E = J.times(J).minus(A).minus(B);
  var G = D.plus(B);
  var F = G.minus(C);
  var H = D.minus(B);
  return [E.times(F), G.times(H), F.times(G), E.times(H)];
}

function xpt_mult(pt, n) {
  if (n.equals(zero)) return [zero, one, one, zero];
  var odd = n.isOdd();
  n.shiftRight(1);
  var _ = xpt_double(xpt_mult(pt, n));
  return odd ? xpt_add(_, pt) : _ ;
}

function pt_xform(pt) {
  var x = pt[0];
  var y = pt[1];
  return [x, y, one, x.times(y)]
}

function pt_unxform (pt) {
  var x = pt[0];
  var y = pt[1];
  var z = pt[2];
  var invz = z.inv();
  return [x.times(invz), y.times(invz)]
}

function scalarmult(pt, n) {
  return pt_unxform(xpt_mult(pt_xform(pt), n));
}

function bytesgetbit(bytes, n) {
  return (bytes[bytes.length-Math.floor(n/8)-1]>>(n%8)) & 1;
}

function xpt_mult_bytes(pt, bytes) {
  var r = [zero, one, one, zero];
  for (var i=bytes.length*8-1; i>=0; i--) {
    r = xpt_double(r);
    if (bytesgetbit(bytes, i)===1) r = xpt_add(r, pt);
  }
  return r;
}

function scalarmult_bytes(pt, bytes) {
  return pt_unxform(xpt_mult_bytes(pt_xform(pt), bytes));
}

var by = bi255('4').divide(bi255('5'));
var bx = xrecover(by);
var bp = [bx, by]

function encodeint(n) { return n.bytes(32).reverse(); }
function decodeint(b) { return bi255(b.slice(0).reverse()); }

function encodepoint(p) {
  var v = encodeint(p[1]);
  if (p[0].isOdd()) v[31] |= 0x80;
  return v;
}

function decodepoint(v) {
  v = v.slice(0);
  var signbit = v[31]>>7;
  v[31] &= 127;
  var y = decodeint(v);
  var x = xrecover(y);
  if ((x.n[0]&1) !== signbit) x = q.minus(x);
  var p = [x,y];
  if (!isoncurve(p)) throw('Point is not on curve');
  return p;
}

////////////////////////////////////////////////////

load('../forge/js/jsbn.js');

// BigInteger construction done right
function bi(s, base) {
  if (base != undefined) {
    if (base == 256) return bi(string2bytes(s));
    return new BigInteger(s, base);
  } else if (typeof s == 'string') {
    return new BigInteger(s, 10);
  } else if (s instanceof Array) {
    return new BigInteger(s);
  } else if (typeof s == 'number') {
    return new BigInteger(s.toString(), 10);
  } else {
    throw "Can't convert " + s + " to BigInteger";
  }
}

function bi2bytes(n, cnt) {
  if (cnt==undefined) cnt = Math.round((n.bitLength()+7)/8);
  var bytes = new Array(cnt);
  for (var i = cnt-1; i>=0; i--) {
    bytes[i] = n[0]&255;           // n.and(xff);
    n = n.shiftRight(8);
  }
  return bytes;
}

BigInteger.prototype.toSource = function() { return this.toString(16) + 'L'; }
BigInteger.prototype.bytes = function (n) { return bi2bytes(this, n); }

///////////////////////////////////////////////////////////

var window = {}
load('../jsSHA/src/sha512.js');
var jsSHA = window.jsSHA

function sha512(s) {
  var shaObj = new jsSHA(s, "ASCII");
  return shaObj.getHash("SHA-512", "HEX");
}

function bytehash(s) {
  return bi2bytes(bi(sha512(s), 16), 64).reverse();
}

function stringhash(s) {
  return map(chr, bi2bytes(bi(sha512(s), 16), 64)).join('');
}

function inthash(s) {
  // Need a leading 0 to prevent sign extension
  return bi([0].concat(bytehash(s)));
}

function inthash_lo(s) {
  return bi255(bytehash(s).slice(32,64));
}

var l_BI = bi(l.toString(), 16);

function inthash_mod_l(s) {
  return inthash(s).mod(l_BI);
}

function publickey(sk) {
  var h = inthash_lo(sk);
  h.n[0] &= 0xfff8;
  h.n[15] &= 0x3fff;
  h.n[15] |= 0x4000;
  return encodepoint(scalarmult(bp, h));
}

function map(f, l) {
  var result = new Array(l.length);
  for (var i=0; i<l.length; i++) result[i]=f(l[i]);
  return result;
}

function chr(n) { return String.fromCharCode(n); }
function ord(c) { return c.charCodeAt(0); }
function bytes2string(bytes) { return map(chr, bytes).join(''); }
function string2bytes(s) { return map(ord, s); }

function signature(m, sk, pk) {
  if (pk === undefined) pk = publickey(sk);
  var a = inthash_lo(sk);
  a.n[0] &= 0xfff8;
  a.n[15] &= 0x3fff;
  a.n[15] |= 0x4000;
  a = bi(a.toString(), 16);
  var hs = stringhash(sk);
  var r = bytehash(hs.slice(32,64) + m);
  var rp = scalarmult_bytes(bp, r);
  var erp = encodepoint(rp);
  r = bi(r).mod(bi('1').shiftLeft(512));
  var s = map(chr, erp).join('') + map(chr,pk).join('') + m;
  s = inthash_mod_l(s).multiply(a).add(r).mod(l_BI);
  return erp.concat(encodeint(s));
}

function pt_add(p1, p2) {
  return pt_unxform(xpt_add(pt_xform(p1), pt_xform(p2)));
}

function checksig(sig, msg, pk) {
  var rpe = sig.slice(0, 32);
  var rp = decodepoint(rpe);
  var a = decodepoint(pk);
  var s = decodeint(sig.slice(32, 64));
  var h = inthash(bytes2string(rpe.concat(pk)) + msg);
  var v1 = scalarmult(bp, s);
  var _ = scalarmult_bytes(a, bi2bytes(h));
  var v2 = pt_add(rp, _);
  return v1[0].equals(v2[0]) && v1[1].equals(v2[1]);
}

function rnd() {
  var s = Math.random().toString();
  for (var i=0; i<8; i++) s = s + Math.random().toString();
  return inthash_lo(s);
}

function sig_test(msg, key) {
  msg = msg || ''+rnd();
  key = key || ''+rnd();
  var pk = publickey(key);
  var sig = signature(msg, key, pk);
  return checksig(sig, msg, pk);
}

////////////////////////////////////
//
// Diffie-Helman key exchange
//

function dhsk() {  // Diffie-Helman secret key
  var sk = rnd();
  sk.n[0] = sk.n[0] & 0xFFF8;
  sk.n[15] = sk.n[15] & 0x7fff | 0x4000;
  return sk;
}

var nine_bi255 = bi255('9');
var zero_bi255s = bi255('0').toString();

function curve25519_bi255(sk, bp) {
  if (!bp) bp = nine_bi255;
  return bi255(curve25519(sk.n, bp.n)).modq();
}

function dh_test() {
  var sk1 = dhsk();
  var sk2 = dhsk();
  var pk1 = curve25519_bi255(sk1);
  var pk2 = curve25519_bi255(sk2);
  var ss1 = curve25519_bi255(sk1, pk2);
  var ss2 = curve25519_bi255(sk2, pk1);
  if (ss1.minus(ss2).toString() == zero_bi255s) return true;
  print('DH TEST FAILED! ' + [sk1, sk2]);
}

function test() {
  print(sig_test('msg','key'));
  print(sig_test('foo','baz'));
  print(sig_test());
  print(dh_test());
}
