# -*- coding: utf-8 -*-
"""把五块拼图串成一条链路：/get -> 识别缺口 -> 生成轨迹 -> 生成 data -> /check

    /api/v3/get   get_live.py 的 fire()        -> 挑战图 + 本次的 token
    识别缺口       识别/识别.py 的 locate_gap()  -> 缺口自然像素 x
    生成轨迹       分析/轨迹生成.py from_gap()   -> [[x,y,t,flag],...]
    生成 data      node 参数生成.js（吃 YD_TOKEN/YD_LEFT/YD_TRACE 环境变量）
    /api/v3/check  本文件 check()               -> 判定

用法
    python 分析/跑一遍.py dry        不联网：用 识别/live_bg.jpg + live_front.png 走一遍前四步，只打印
    python 分析/跑一遍.py build      从线上拿一组新挑战，算好并打印完整 check URL（**不发**）
    python 分析/跑一遍.py send       同上，并把 /check 真发出去
    python 分析/跑一遍.py send 3     连打 3 次

⚠ /check 会真的提交到 c.dun.163.com。默认（dry/build）都不发。
"""
import json
import os
import random
import string
import subprocess
import sys
import urllib.parse
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, '识别'))

import get_live                       # noqa: E402  /get 的发包与 cb
import 轨迹生成                        # noqa: E402

CHECK_PATH = '/api/v3/check'
TRACE_TMP = os.path.join(HERE, '.trace.json')
DATA_TMP = os.path.join(HERE, '.data.json')


def verify_data(data, token):
    """把 data 落盘跑一遍 校验data.js，反解回明文自检。返回 True/False。"""
    with open(DATA_TMP, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)
    p = subprocess.run(['node', os.path.join(HERE, '校验data.js'), token, DATA_TMP],
                       cwd=ROOT, capture_output=True)
    print(p.stdout.decode('utf-8', 'replace').rstrip())
    if p.returncode != 0:
        err = p.stderr.decode('utf-8', 'replace').strip()
        if err:
            print(err[-800:])
    return p.returncode == 0


# ────────────────────────────────────────────── 1. 拿挑战
def fetch_challenge():
    """复用 get_live 的抓包参数，只换 cb。返回 (挑战 dict, 用到的会话参数 dict)。"""
    params = [(k, get_live.gen_cb() if k == 'cb' else v) for k, v in get_live.CAPTURED]
    r = get_live.fire(params, 'challenge')
    body = r.get('json') or {}
    d = body.get('data') or {}
    if not d.get('bg') or not d.get('token'):
        raise SystemExit('没拿到挑战：http=%s verdict=%s body=%s'
                         % (r.get('http'), r.get('verdict'), json.dumps(body)[:300]))
    return d, dict(params)


# ────────────────────────────────────────────── 2. 识别缺口
def find_gap(bg_url, front_url):
    """下载 bg/front 并定位缺口。返回 (缺口自然像素 x, 明细)。"""
    import 识别
    bg = _download(bg_url)
    front = _download(front_url)
    box = 识别.locate_gap(front, bg)
    return box['x'], box


def _download(url):
    req = urllib.request.Request(url, headers={'User-Agent': get_live.HEADERS['User-Agent']})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


# ────────────────────────────────────────────── 3+4. 轨迹 -> data
def build_data(token, left_css, trace):
    """把轨迹写临时文件，让 参数生成.js 吃环境变量吐 d/m/p/f/ext。"""
    with open(TRACE_TMP, 'w', encoding='utf-8') as f:
        json.dump(trace, f, ensure_ascii=False)

    env = dict(os.environ)
    env['YD_TOKEN'] = token
    env['YD_LEFT'] = str(left_css)
    env['YD_TRACE'] = TRACE_TMP
    p = subprocess.run(['node', '参数生成.js'], cwd=ROOT, env=env, capture_output=True)
    txt = p.stdout.decode('utf-8', 'replace')
    if p.returncode != 0:
        raise SystemExit('参数生成.js 失败：\n%s' % p.stderr.decode('utf-8', 'replace')[-1500:])
    for line in reversed(txt.splitlines()):
        if line.startswith('{"d":'):
            return json.loads(line)
    raise SystemExit('参数生成.js 没吐出 JSON：\n%s' % txt[-800:])


# ────────────────────────────────────────────── 5. 发 /check
def build_check_url(sess, data, cb, callback):
    order = ['referer', 'zoneId', 'dt', 'id', 'token', 'data', 'width', 'type',
             'version', 'cb', 'user', 'extraData', 'bf', 'runEnv', 'sdkVersion',
             'loadVersion', 'iv', 'callback']
    v = {
        'referer': 'https://dian2.ysbang.cn/#/login',
        'zoneId': sess.get('zoneId', 'CN31'),
        'dt': sess['dt'], 'id': sess['id'], 'token': sess['token'],
        'data': json.dumps(data, separators=(',', ':')),
        'width': '270', 'type': '2', 'version': '2.28.5',
        'cb': cb, 'user': '', 'extraData': '', 'bf': '0', 'runEnv': '10',
        'sdkVersion': '', 'loadVersion': '2.5.4', 'iv': '4', 'callback': callback,
    }
    qs = '&'.join('%s=%s' % (k, urllib.parse.quote(str(v[k]), safe='')) for k in order)
    return 'https://c.dun.163.com' + CHECK_PATH + '?' + qs


def fire_check(url):
    req = urllib.request.Request(url, headers=get_live.HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, 'EXC %s' % e


def jsonp(body):
    i, j = body.find('('), body.rfind(')')
    if i < 0 or j < 0:
        return None
    try:
        return json.loads(body[i + 1:j])
    except ValueError:
        return None


def rand_callback(n=8):
    return '__JSONP_' + ''.join(random.choice(string.ascii_lowercase + string.digits)
                                for _ in range(n)) + '_0'


# ────────────────────────────────────────────── 主流程
def one_shot(sess, token, gap_x, trace, label='', send=False):
    left = trace[-1][0]
    print('%s缺口 x=%.1f(自然) -> 落点 left=%d(css)  轨迹 %d 点'
          % (label, gap_x, left, len(trace)))
    issues = 轨迹生成.check(trace, verbose=False)
    print('%s轨迹自检：%s' % (label, '通过' if not issues else '⚠ ' + '; '.join(issues[:3])))

    data = build_data(token, left, trace)
    print('%sdata 自检：' % label)
    verify_data(data, token)
    cb = get_live.gen_cb()
    url = build_check_url(sess, data, cb, rand_callback())
    print('%scheck URL %d 字符：%s…' % (label, len(url), url[:110]))

    if not send:
        print('%s（未发送）' % label)
        return None
    http, body = fire_check(url)
    j = jsonp(body) or {}
    print('%s发送 http=%s -> %s' % (label, http, json.dumps(j, ensure_ascii=False)[:400]))
    return j


def main(argv):
    mode = argv[1] if len(argv) > 1 else 'dry'
    n = int(argv[2]) if len(argv) > 2 else 1

    if mode == 'dry':
        bg = os.path.join(ROOT, '识别', 'live_bg.jpg')
        fr = os.path.join(ROOT, '识别', 'live_front.png')
        import 识别
        box = 识别.locate_gap(open(fr, 'rb').read(), open(bg, 'rb').read())
        gap = box['x']
        trace = 轨迹生成.from_gap(gap)
        cap = dict(get_live.CAPTURED)
        sess = {'dt': '(dry)', 'id': cap['id'], 'token': '(dry)', 'zoneId': cap['zoneId']}
        one_shot(sess, 'drytoken0000000000000000000000000', gap, trace, label='[dry] ')
        return 0

    if mode not in ('build', 'send'):
        print(__doc__)
        return 1

    for i in range(n):
        label = '[%d/%d] ' % (i + 1, n) if n > 1 else ''
        d, params = fetch_challenge()
        sess = dict(params)
        sess['token'] = d['token']          # /check 回显的是 /get 响应里发的 token
        print('%s挑战 token=%s zoneId=%s bg=%s'
              % (label, d['token'], d.get('zoneId'), d['bg'][0].rsplit('/', 1)[-1]))
        gap, box = find_gap(d['bg'][0], d['front'][0])
        print('%s识别：x=%d y=%d w=%d h=%d method=%s score=%.3f'
              % (label, box['x'], box['y'], box['w'], box['h'], box['method'], box['score']))
        trace = 轨迹生成.from_gap(gap)
        one_shot(sess, d['token'], gap, trace, label=label, send=(mode == 'send'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
