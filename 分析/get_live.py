"""对 /api/v3/get 发包验证。

抓包来源: c.dun.163.com/api/v3/get (GET, JSONP)
固定参数 + 会话参数(dt/irToken/id/fp) 全部沿用抓包, 只把 cb 换成我们自己算的,
用来判断 cb.js 生成的 cb 是否被服务端接受。

    python 分析/get_live.py dry      # 只打印(不联网): URL + cb 格式校验
    python 分析/get_live.py replay   # 原样重放抓包 URL(基线, 发 1 次)
    python 分析/get_live.py cb       # 只换 cb 为本地新算的(发 1 次)
    python 分析/get_live.py both     # 上面两个各发 1 次
    python 分析/get_live.py save     # 发 1 次, 拿一组挑战并把 bg/front 落到 img/
    python 分析/get_live.py save 10  # 连发 10 次, 落 10 组

判定: HTTP 200 不代表通过, 必须看 body 的 error / msg / data 载荷。
    error:0 + msg:'ok' + data 里有 bg/front/token  -> 通过, 拿到挑战
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = 'https://c.dun.163.com'
PATH = '/api/v3/get'
IMG_DIR = os.path.join(HERE, 'img')

# cb 的字母表与填充字符（来自 cb.js: _0x3c38ba / _0x453667）
ALPHABET = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo"
PAD = '7'

# 抓包原样（已是 URL 解码后的值）
CAPTURED = [
    ('referer', 'https://dian2.ysbang.cn/#/login'),
    ('zoneId', 'CN31'),
    ('dt', 'AlG+x3oVFG9EV1AFFVPYALB7w/Ob1s1m'),
    ('irToken', 'H3ceNIfbu7ZEZwEFFBeMQeCjhLVlFGFI'),
    ('id', 'fdca1afff60e43c2846b1e9285bc7180'),
    ('fp', 'skYdWVGKoBrLboI1WJCKrzaHL+JJ/B/cm96zf/3b48UvD/sRLgTKx98TkxzD5BXNpE'
           'NoIZ9p9DZkVT36SvXE+0iMUNlTVuIR4hyQtLwX4fXhG\\VCT3oaLM0LveU+BUM7qvJcUda'
           '+85vU1GJc3vZQqKMmqwzU91\\4NzZIMdklTQ/8mlAX:1790155759754'),
    ('https', 'true'),
    ('type', ''),
    ('version', '2.28.5'),
    ('dpr', '1.5'),
    ('dev', '3'),
    ('cb', 'cE9vqzEVVLkRMw3LBEawvm+.6LMtSqU/8UyOL3Qoj6hoPSbFQVNeHmwf1wjTt6Suqzk5j'
           'SFfAtyG2Y62pdX1sTwGwOx7'),
    ('ipv6', 'false'),
    ('runEnv', '10'),
    ('group', ''),
    ('scene', ''),
    ('lang', 'zh-CN'),
    ('sdkVersion', ''),
    ('loadVersion', '2.5.4'),
    ('iv', '4'),
    ('user', ''),
    ('width', '270'),
    ('audio', 'false'),
    ('sizeType', '10'),
    ('smsVersion', 'v3'),
    ('token', ''),
    ('callback', '__JSONP_k4fz91b_0'),
]

HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Referer': 'https://dian2.ysbang.cn/',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-Fetch-Storage-Access': 'none',
    'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36'),
    'sec-ch-ua': '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}


# ---------------------------------------------------------------- cb 格式

def cb_decode(cb):
    """按 cb.js 的 _0x2d84c6/_0x4c4b3e 逆运算把 cb 解回字节。"""
    out = []
    for i in range(0, len(cb), 4):
        g = cb[i:i + 4]
        c = [ALPHABET.find(ch) for ch in g]
        if c[0] < 0 or c[1] < 0 or c[2] < 0:
            raise ValueError('非字母表字符 @ %d: %r' % (i, g))
        out.append((c[0] << 2) | (c[1] >> 4))
        out.append(((c[1] & 0xF) << 4) | (c[2] >> 2))
        if c[3] >= 0:                      # 第 4 位是填充则只出 2 字节
            out.append(((c[2] & 3) << 6) | c[3])
        elif g[3] != PAD:
            raise ValueError('填充位不是 %r @ %d: %r' % (PAD, i, g))
    return out


def cb_check(cb, tag):
    """打印 cb 的结构指纹，返回 (是否合法, 字节列表)。"""
    try:
        b = cb_decode(cb)
    except ValueError as e:
        print('  %-8s 非法: %s' % (tag, e))
        return False, []
    seed = ' '.join('%02x' % x for x in b[:4])
    ok = len(cb) == 92 and len(b) == 68 and cb[-1] == PAD
    print('  %-8s len=%-3d bytes=%-3d 尾=%r  seed=%s  %s'
          % (tag, len(cb), len(b), cb[-1], seed, 'OK' if ok else '!! 长度/尾字符异常'))
    return ok, b


def gen_cb():
    """跑 cb.js 拿一个全新的 cb。"""
    p = subprocess.run(['node', os.path.join(HERE, 'cb.js')],
                       cwd=HERE, capture_output=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError('node cb.js 失败: %s' % p.stderr.decode('utf-8', 'replace'))
    return p.stdout.decode('utf-8', 'replace').strip().splitlines()[-1].strip()


# ---------------------------------------------------------------- 发包

def build(params):
    # quote_via=quote + safe='' 才能复刻抓包里的 %2B / %2F / %3A
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, safe='')
    return '%s%s?%s' % (HOST, PATH, qs)


def jsonp(body):
    m = re.match(r'^\s*[\w.$]*\s*\((.*)\)\s*;?\s*$', body, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except ValueError:
        return None


def fire(params, label):
    url = build(params)
    t0 = time.time()
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            http, body = r.status, r.read().decode('utf-8', 'replace')
    except Exception as e:
        http, body = 'ERR', '%s: %s' % (type(e).__name__, e)
    ms = int((time.time() - t0) * 1000)

    js = jsonp(body)
    if js is None:
        print('  %-8s http=%-4s 非 JSONP, body 前 160 字: %s  %dms'
              % (label, http, repr(body[:160]), ms))
        return {'label': label, 'http': http, 'body': body, 'json': None,
                'verdict': '解析失败', 'ms': ms}

    d = js.get('data') or {}
    err = js.get('error')
    if err == 0 and all(k in d for k in ('bg', 'front', 'token')):
        verdict = 'PASS 拿到挑战'
    elif err == 0:
        verdict = '退化 无挑战载荷'
    else:
        verdict = '拒绝'
    print('  %-8s http=%-4s error=%-4s msg=%-6s type=%-3s token=%-34s %s  %dms'
          % (label, http, err, str(js.get('msg'))[:6], d.get('type'),
             str(d.get('token'))[:34], verdict, ms))
    return {'label': label, 'http': http, 'body': body, 'json': js, 'ms': ms,
            'verdict': verdict}


# ---------------------------------------------------------------- 落图

def _fetch_bytes(v, timeout=15, retries=3):
    """data['bg'] / data['front'] 的元素：可能是 CDN URL，也可能是 base64。

    实测 v3 返回的是 URL，形如
        https://necaptcha.nosdn.127.net/8c7fb752320e449c8ae49ac82f7278b2.jpg

    CDN 偶尔会甩 SSL UNEXPECTED_EOF 之类的瞬时错误，重试几次就好 ——
    不重试的话一次抖动会把整批循环带崩。
    """
    if not isinstance(v, str):
        raise TypeError('期望字符串，拿到 %r' % type(v).__name__)
    s = v.strip()
    if s.startswith(('http://', 'https://')):
        last = None
        for i in range(retries):
            try:
                req = urllib.request.Request(s, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.read()
            except Exception as e:
                last = e
                if i + 1 < retries:
                    time.sleep(0.8 * (i + 1))
        raise RuntimeError('下载 %s 失败（试了 %d 次）: %s' % (s, retries, last))
    if s.startswith('data:'):
        s = s.split(',', 1)[1]
    # 容忍 URL-safe 字母表和缺失的 padding
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _sniff(raw):
    if raw[:2] == b'\xff\xd8':
        return 'jpg'
    if raw[:4] == b'\x89PNG':
        return 'png'
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'webp'
    return 'bin'


def save_images(data, prefix=None, img_dir=IMG_DIR):
    """把 data['bg'] / data['front'] 落盘。返回写出的路径列表。

    同一个 key 下可能有多个条目（实测各 2 个），内容相同的只存一份。
    名字带时间戳前缀，不会覆盖已有的参考图。
    """
    os.makedirs(img_dir, exist_ok=True)
    if prefix is None:
        prefix = time.strftime('live_%Y%m%d_%H%M%S')
    out, seen = [], set()
    for key in ('bg', 'front'):
        val = data.get(key)
        if val is None:
            print('  !! data 里没有 %r' % key)
            continue
        items = val if isinstance(val, list) else [val]
        n = 0
        for item in items:
            raw = _fetch_bytes(item)
            h = hashlib.sha1(raw).digest()
            if h in seen:                      # 同图不同格式，跳过重复
                continue
            seen.add(h)
            ext = _sniff(raw)
            stem = key if n == 0 else '%s_%d' % (key, n)
            n += 1
            p = os.path.join(img_dir, '%s_%s.%s' % (prefix, stem, ext))
            with open(p, 'wb') as f:
                f.write(raw)
            out.append(p)
            src = item if item.startswith('http') else '<base64>'
            print('  %-9s %7d B  %-5s %s' % (key, len(raw), ext, p))
            print('  %-9s           来源: %s' % ('', src[:100]))
    return out


# ---------------------------------------------------------------- main

def main(argv):
    mode = argv[1] if len(argv) > 1 else 'dry'
    cap = dict(CAPTURED)

    if mode == 'dry':
        print('=== dry: 不联网 ===')
        print('  抓包 cb  :')
        cb_check(cap['cb'], 'captured')
        fresh = gen_cb()
        print('  本地 cb  :')
        cb_check(fresh, 'fresh')
        print('  URL 长度 : %d' % len(build(CAPTURED)))
        print('  %s' % build(CAPTURED)[:150] + ' ...')
        return 0

    rows = []
    if mode == 'save':
        n = int(argv[2]) if len(argv) > 2 else 1
        print('=== save: 拿 %d 组挑战并落图 ===' % n)
        last = None
        for i in range(n):
            # 落图前缀精确到秒，同一秒内的两次会互相覆盖，等过完这一秒再发
            while True:
                prefix = time.strftime('live_%Y%m%d_%H%M%S')
                if prefix != last:
                    break
                time.sleep(0.2)
            last = prefix
            tag = '' if n == 1 else '#%d' % (i + 1)
            fresh = gen_cb()
            cb_check(fresh, 'fresh' + tag)
            params = [(k, fresh if k == 'cb' else v) for k, v in CAPTURED]
            r = fire(params, 'save' + tag)
            rows.append(r)
            d = (r.get('json') or {}).get('data') or {}
            if 'bg' in d and 'front' in d:
                try:
                    save_images(d, prefix=prefix)
                except Exception as e:      # 落图失败不该拖垮整批
                    print('  !! 落图失败: %s' % e)
            else:
                print('  !! 未拿到 bg/front，没落图')
            if i + 1 < n:
                time.sleep(0.5)

    if mode in ('replay', 'both'):
        print('=== replay: 原样重放抓包参数（基线）===')
        rows.append(fire(CAPTURED, 'replay'))

    if mode in ('cb', 'both'):
        print('=== cb: 只把 cb 换成本地新算的 ===')
        fresh = gen_cb()
        cb_check(fresh, 'fresh')
        params = [(k, fresh if k == 'cb' else v) for k, v in CAPTURED]
        rows.append(fire(params, 'fresh-cb'))

    print()
    for r in rows:
        print('%-10s http=%-4s %s' % (r['label'], r['http'], r['verdict']))
    out = os.path.join(HERE, 'get_rows.json')
    old = json.load(open(out, encoding='utf-8')) if os.path.exists(out) else []
    json.dump(old + rows, open(out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print('记录 -> %s（累计 %d 条）' % (out, len(old) + len(rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
