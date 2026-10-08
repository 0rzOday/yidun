// 自检：把 参数生成.js 吐出来的 data 反解回明文，看四个字段是否自洽。
//   node 分析/校验data.js <token> <data-json文件>
// 期望：
//   p    = 滑动距离/270*100 的字符串
//   ext  = "1,轨迹点数"
//   f    = 47 个数
//   d    = 50 段采样，每段 [x,y,t,flag]
var fs = require('fs');
var D = require('./解密.js');

var token = process.argv[2];
var data = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));

function field(k) {
  var r = D.decodeField(data[k], token);
  return { plain: r.plain, crcOk: r.crcOk, n: r.n };
}

var ok = true;
function say(tag, good, msg) {
  if (!good) ok = false;
  console.log((good ? '  ✓ ' : '  ✗ ') + tag + '  ' + msg);
}

console.log('token = ' + token);

var p = field('p');
say('p  ', p.crcOk && /^\d+(\.\d+)?$/.test(p.plain || ''), JSON.stringify(p.plain) + '  (CRC ' + p.crcOk + ')');

var ext = field('ext');
var extN = (ext.plain || '0,0').split(',')[1];
say('ext', ext.crcOk && /^\d+,\d+$/.test(ext.plain || ''), JSON.stringify(ext.plain));

var f = field('f');
var fArr = (f.plain || '').split(',');
say('f  ', f.crcOk && fArr.length === 47, fArr.length + ' 个数');

var d = D.decodeD(data.d, token, parseInt(extN, 10) || 0);
var bad = d.rows.filter(function (r) { return !r || r.length !== 4; }).length;
say('d  ', d.segs.length === 50 && bad === 0, d.segs.length + ' 段, 坏 ' + bad + ' 段');

console.log('  d 采样（轨迹下标 / [x,y,t,flag]）:');
d.rows.forEach(function (r, i) {
  if (i % 7 === 0 || i === d.rows.length - 1)
    console.log('    ' + String(d.idx[i]).padStart(5) + '  ' + JSON.stringify(r));
});

// left 反推：p 的明文是 left/270*100
var leftCss = p.plain ? Math.round(parseFloat(p.plain) / 100 * 270) : null;
console.log('\n反推滑动距离 left = ' + leftCss + ' css px');
console.log('轨迹点数 = ' + extN + '，采样段数 = ' + d.segs.length);
console.log(ok ? '\n✅ data 自洽' : '\n❌ data 有问题');
process.exit(ok ? 0 : 1);
