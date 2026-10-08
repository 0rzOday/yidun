// 易盾 _0x3ebd00（AES 层）的**逆运算** + xorDecode，用来把真抓包还原成明文。
//
// 为什么能逆：_0x34ece2 那 7 个轮函数全是逐字节的加/减/异或，字节之间没有扩散，
// 位置相关的密钥由 __ROUND_KEY__ 的十六进制对给出；唯一的非线性是链式那步的
// sbox(sbox(x))，而 __SBOX__ 是 0..255 的完整排列，取两次逆表即可。
//
// 加密（_0x3ebd00）每个 64 字节分组：
//     A = R(block) ^ key                 R = _0x34ece2
//     B = A + prev                       （逐字节加，按 prev 循环）
//     C = B ^ prev
//     输出块 = sbox(sbox(C))              prev 更新为「输出块」
// 解密就倒着走一遍。
//
// 用法
//   node 分析/解密.js <密文>              自动判层：先按 AES 表解，再按需 xorDecode
//   node 分析/解密.js --f <f密文>         解 f 并尝试 xorDecode 成 47 个数
//   node 分析/解密.js --file 分析/check_pkt.txt   直接解整包

var __SBOX__ = 'a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194dac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaad0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e';
var SEED_KEY = 'fd6a43ae25f74398b61c03c83be37449';
var ROUND_KEY = '037606da0296055c';

var AES_ALPHA = 'MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo';
var AES_PAD = '7';
var XOR_ALPHA = 'i/x1XgU0z7k8N+lCpOnPrv6\\qu2Gj9HRcwTYZ4bfSJBhaWstAeoMIEQ5mDdVFLKy';
var XOR_PAD = '3';

var SBOX = [], ISBOX = [];
__SBOX__.replace(/../g, function (h, i) { SBOX[i / 2] = parseInt(h, 16); });
SBOX.forEach(function (v, i) { ISBOX[v] = i; });


// ── 基础字节工具 ────────────────────────────────────────────────────────
function toByte(v) { v &= 0xff; return v > 0x7f ? v - 0x100 : v; }
function u8(v) { return toByte(v) & 0xff; }

function stringToBytes(s) {
  var enc = encodeURIComponent(s), out = [];
  for (var i = 0; i < enc.length; i++) {
    if (enc.charAt(i) === '%') out.push(parseInt(enc.substr(++i, 2), 16)), i++;
    else out.push(u8(enc.charCodeAt(i)));
  }
  return out;
}

function bytesToString(b) {
  var parts = [];
  for (var i = 0; i < b.length; i++) parts.push('%' + u8(b[i]).toString(16).padStart(2, '0'));
  return decodeURIComponent(parts.join(''));
}

function b64decode(s, alpha, pad) {
  var PAD = pad === undefined ? '=' : pad;
  s = String(s).replace(/[\s]/g, '');
  while (s.length && s.charAt(s.length - 1) === PAD) s = s.slice(0, -1);
  var idx = {};
  for (var i = 0; i < alpha.length; i++) idx[alpha.charAt(i)] = i;
  var bits = '';
  for (var j = 0; j < s.length; j++) {
    var v = idx[s.charAt(j)];
    if (v === undefined) throw new Error('不在字母表里的字符: ' + JSON.stringify(s.charAt(j)));
    bits += ('000000' + v.toString(2)).slice(-6);
  }
  var out = [];
  for (var k = 0; k + 8 <= bits.length; k += 8) out.push(parseInt(bits.substr(k, 8), 2));
  return out;
}

// _0x17d8ba：不足 64 就循环补齐，够了就取前 64
function pad64(a) {
  if (!a.length) return new Array(64).fill(0);
  if (a.length >= 64) return a.slice(0, 64);
  var out = [];
  for (var i = 0; i < 64; i++) out[i] = a[i % a.length];
  return out;
}

function xors(a, b) {
  var out = [];
  for (var i = 0; i < a.length; i++) out[i] = u8(a[i] ^ b[i % b.length]);
  return out;
}

function adds(a, b) {   // _0x474f75 'shifts'
  var out = [];
  for (var i = 0; i < a.length; i++) out[i] = u8(a[i] + b[i % b.length]);
  return out;
}

function subs(a, b) {   // 加法的逆
  var out = [];
  for (var i = 0; i < a.length; i++) out[i] = u8(a[i] - b[i % b.length]);
  return out;
}

function sbox2(a) { return a.map(function (v) { return SBOX[SBOX[u8(v)]]; }); }
function isbox2(a) { return a.map(function (v) { return ISBOX[ISBOX[u8(v)]]; }); }


// ── _0x34ece2 及其逆 ────────────────────────────────────────────────────
// rounds[idx](x, arg) 对每个字节做位置相关的变换
var ROUNDS = [
  function (x) { return x; },                                                   // 0 恒等
  function (x, a) { return x.map(function (v) { return u8(v ^ a); }); },        // 1 xor 定值
  function (x, a) { return x.map(function (v) { return u8(v + a); }); },        // 2 add 定值
  function (x, a) { return x.map(function (v, i) { return u8(v ^ (a + i)); }); }, // 3 xor 递增
  function (x, a) { return x.map(function (v, i) { return u8(v + a + i); }); },   // 4 add 递增
  function (x, a) { return x.map(function (v, i) { return u8(v ^ (a - i)); }); }, // 5 xor 递减
  function (x, a) { return x.map(function (v, i) { return u8(v + a - i); }); }    // 6 add 递减
];

function roundSeq() {
  var seq = [];
  for (var i = 0; i < ROUND_KEY.length; i += 4) {
    var idx = parseInt(ROUND_KEY.substr(i, 2), 16);
    var arg = parseInt(ROUND_KEY.substr(i + 2, 2), 16);
    seq.push([idx, arg]);
  }
  return seq;
}
var SEQ = roundSeq();

function R(x) {           // _0x34ece2
  SEQ.forEach(function (p) { x = ROUNDS[p[0]](x, p[1]); });
  return x;
}
function Rinv(x) {        // 倒着走，并且把加换成减
  for (var i = SEQ.length - 1; i >= 0; i--) {
    var idx = SEQ[i][0], arg = SEQ[i][1];
    if (idx === 1 || idx === 3 || idx === 5) x = ROUNDS[idx](x, arg);          // xor 自逆
    else if (idx === 2) x = ROUNDS[idx](x, -arg);                             // add -> sub
    else if (idx === 4) x = x.map(function (v, k) { return u8(v - arg - k); });
    else if (idx === 6) x = x.map(function (v, k) { return u8(v - arg + k); });
  }
  return x;
}


// ── _0x3ebd00 的解密 ────────────────────────────────────────────────────
// 返回 { bytes, n }：bytes 是去掉填充后的明文（P + CRC 尾巴），n 是长度字段里的值。
function aesDecryptBytes(cipher) {
  var raw = b64decode(cipher, AES_ALPHA, AES_PAD);
  if (raw.length < 4 || (raw.length - 4) % 64 !== 0)
    throw new Error('长度不对：' + raw.length + ' 字节（应为 4 + 64n）');

  var iv = raw.slice(0, 4);
  var key = pad64(stringToBytes(SEED_KEY));
  key = xors(key, pad64(iv));
  key = pad64(key);

  var prev = key, out = [];
  for (var off = 4; off < raw.length; off += 64) {
    var c = raw.slice(off, off + 64);
    var C = isbox2(c);
    var B = xors(C, prev);
    var A = subs(B, prev);
    out = out.concat(Rinv(xors(A, key)));
    prev = c;
  }

  // _0x5dfb84 的填充：末尾 4 字节大端原长
  var n = ((out[out.length - 4] << 24) | (out[out.length - 3] << 16) |
    (out[out.length - 2] << 8) | out[out.length - 1]) >>> 0;
  if (n > out.length - 4) n = out.length - 4;
  return { bytes: out.slice(0, n), n: n, full: out, iv: iv };
}

function aesDecrypt(cipher) {
  return bytesToString(aesDecryptBytes(cipher).bytes);
}

// xorDecode（_0x235465），用 XOR_ALPHA 那张表
function xorDecode(token, s) {
  var b = b64decode(s, XOR_ALPHA, XOR_PAD);
  return bytesToString(xors(b, stringToBytes(token)));
}

// xorEncode（_0x3855dc）—— 反向，用来做回编码自检
function b64encode(a, alpha, pad) {
  var bits = '';
  for (var i = 0; i < a.length; i++) bits += ('00000000' + u8(a[i]).toString(2)).slice(-8);
  var out = '';
  var full = Math.floor(bits.length / 6);
  for (var k = 0; k < full; k++) out += alpha.charAt(parseInt(bits.substr(k * 6, 6), 2));
  if (full * 6 < bits.length) out += alpha.charAt(parseInt(bits.substr(full * 6), 2) << (6 - (bits.length - full * 6)));
  while (out.length % 4) out += pad;
  return out;
}

function xorEncode(token, s) {
  return b64encode(xors(stringToBytes(s), stringToBytes(token)), XOR_ALPHA, XOR_PAD);
}


// ── 一层到位的入口 ──────────────────────────────────────────────────────
// 明文布局（一个 64 字节分组内）：
//     [ xorEncode 文本 ][ CRC32 的 8 个十六进制字符 ][ 0 填充 ][ 4 字节大端总长 ]
// 注意：被 AES 包住的那层是 xorEncode 的**文本**，不是 47 个数本身；
// 所以还要再过一次 xorDecode 才是真明文。
var CRC_TAB = (function () {
  var t = [];
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes) {
  var c = 0xffffffff;
  for (var i = 0; i < bytes.length; i++) c = CRC_TAB[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ((c ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
}

// d 特殊：它的 AES 明文是 sample(MOVE_CIPHER,50) 用 ':' 拼起来的**密文串**，
// 没有整体 xorEncode 那层，得按 ':' 拆开逐段 xorDecode。其余三个字段才是一整段。
function decodeField(cipher, token) {
  var r = aesDecryptBytes(cipher);
  var b = r.bytes;
  var innerBytes = b.slice(0, b.length - 8);
  var crcInPacket = String.fromCharCode.apply(null, b.slice(b.length - 8));
  var inner = String.fromCharCode.apply(null, innerBytes);
  var plain = null;
  if (token) { try { plain = xorDecode(token, inner); } catch (e) { plain = null; } }
  return {
    inner: inner,          // AES 里的原始明文（xorEncode 文本 / ':' 拼的密文串）
    plain: plain,          // 真明文；d 这种整体解不了的为 null
    crc: crcInPacket,
    crcOk: crc32(innerBytes) === crcInPacket,
    n: r.n,
    iv: r.iv
  };
}

// d -> 50 段密文 -> 50 条 [x,y,t,flag]，以及它们在整条轨迹里的下标。
// sample(arr, m) 的取法是 i*(len-1)/(m-1) 向上取整推进，反推下标要 len（=traceData.length）。
function decodeD(cipher, token, traceLen) {
  var inner = decodeField(cipher, token).inner;
  var segs = inner.split(':');
  var rows = [], idx = [];
  segs.forEach(function (sg) {
    // 解出来是 "4,0,73,1" 这种，得套上方括号才是合法 JSON
    try { rows.push(JSON.parse('[' + xorDecode(token, sg) + ']')); } catch (e) { rows.push(null); }
  });
  if (traceLen > 1 && segs.length > 1) {
    var m = segs.length, j = 0, i = 0;
    for (i = 0; i < traceLen; i++) {
      if (i >= j * (traceLen - 1) / (m - 1)) { idx.push(i); j++; }
    }
  }
  return { segs: segs, rows: rows, idx: idx };
}


// ── 正向：_0x3ebd00 的加密（组装请求时生成 cb 要用） ─────────────────────
function aesEncrypt(input, ivOverride) {
  var P = stringToBytes(input);
  var body = P.concat(stringToBytes(crc32(P)));     // 明文 + CRC32 的 8 个十六进制字符
  var n = body.length, chunk = 64;
  // _0x5dfb84：补 0 到 64 的倍数，但末尾 4 字节留给长度；放不下就多开一组
  var padLen = (n % chunk <= chunk - 4) ? chunk - n % chunk - 4 : 2 * chunk - n % chunk - 4;
  var padded = body.concat(new Array(padLen).fill(0));
  padded.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

  var iv = ivOverride || [0, 0, 0, 0].map(function () { return u8(Math.floor(0x100 * Math.random())); });
  var key = pad64(stringToBytes(SEED_KEY));
  key = xors(key, pad64(iv));
  key = pad64(key);

  var out = iv.slice(), prev = key;
  for (var off = 0; off < padded.length; off += chunk) {
    var A = xors(R(padded.slice(off, off + chunk)), key);
    var B = adds(A, prev);
    var C = xors(B, prev);
    var blk = sbox2(C);
    out = out.concat(blk);
    prev = blk;
  }
  return b64encode(out, AES_ALPHA, AES_PAD);
}

// cb = AES(uuid(32) 的第 [1,10,12,13,26,31] 位换成 'vfnv46')
var UUID_ALPHA = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function genCb() {
  var a = [];
  for (var i = 0; i < 32; i++) a.push(UUID_ALPHA.charAt(Math.floor(Math.random() * UUID_ALPHA.length)));
  var pos = [1, 10, 12, 13, 26, 31], code = 'vfnv46';
  for (var k = 0; k < pos.length; k++) a[pos[k]] = code.charAt(k);
  return aesEncrypt(a.join(''));
}


// ── CLI ─────────────────────────────────────────────────────────────────
function main() {
  var argv = process.argv.slice(2);
  if (!argv.length) {
    console.log('用法: node 分析/解密.js [--token T] [--xor] <密文>');
    console.log('      node 分析/解密.js --file 分析/check_pkt.txt');
    return;
  }
  var token = null, doXor = false, mode = null, val = null;
  for (var i = 0; i < argv.length; i++) {
    if (argv[i] === '--token') token = argv[++i];
    else if (argv[i] === '--xor') doXor = true;
    else if (argv[i] === '--file') mode = 'file', val = argv[++i];
    else val = argv[i];
  }

  if (mode === 'file') {
    var fs = require('fs');
    var line = fs.readFileSync(val, 'utf8').split('\n')[0];
    var q = line.split(' ')[1];
    var m = q.match(/[?&]data=([^&]*)/);
    var dd = JSON.parse(decodeURIComponent(m[1]));
    var t = decodeURIComponent(q.match(/[?&]token=([^&]*)/)[1]);
    console.log('token =', t);
    ['p', 'f', 'ext'].forEach(function (k) {
      console.log('\n--- ' + k + ' ---');
      var r;
      try { r = decodeField(dd[k], t); } catch (e) { console.log('  失败: ' + e.message); return; }
      console.log('  CRC32 ' + (r.crcOk ? '✓ ' : '✗ ') + r.crc);
      if (k === 'f') {
        var arr = r.plain.split(',');
        console.log('  47 个数（' + arr.length + ' 个）:');
        for (var i = 0; i < arr.length; i += 8)
          console.log('    ' + arr.slice(i, i + 8).map(function (v, j) { return (i + j) + ':' + v; }).join('  '));
      } else {
        console.log('  明文: ' + JSON.stringify(r.plain));
      }
    });
    return;
  }

  var s = aesDecrypt(val);
  console.log('AES  ->  ' + JSON.stringify(s));
  if (doXor && token) console.log('XOR  ->  ' + JSON.stringify(xorDecode(token, s)));
}

module.exports = {
  aesDecrypt: aesDecrypt, aesDecryptBytes: aesDecryptBytes,
  xorDecode: xorDecode, xorEncode: xorEncode, R: R, Rinv: Rinv,
  stringToBytes: stringToBytes, bytesToString: bytesToString, b64decode: b64decode,
  decodeField: decodeField, decodeD: decodeD, crc32: crc32,
  aesEncrypt: aesEncrypt, genCb: genCb, b64encode: b64encode
};
if (require.main === module) main();
