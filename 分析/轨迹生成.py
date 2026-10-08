# -*- coding: utf-8 -*-
"""
易盾滑块轨迹生成器

输入缺口水平距离，输出可直接拼进 cb 的 [x, y, t, flag] 点序列。

这份实现不是拍脑袋想的，是从 分析/轨迹{1,2,3}.txt 三份真实插桩数据反推的
（统计脚本见 分析/traj_stats.py，随时可以重跑复核）。三条关键结论：

1. 本体是一条形态恒定的高频抖动流，从头到尾不变。
   按距离切成"前50% / 50-80% / 后20%"三段分别统计，三份数据里
   "移动步占比"都稳定在 61~68%、"平均步长"都稳定在 0.56~0.71px ——
   快拖（轨迹2 全程 895ms）和慢拖（轨迹1 全程 1491ms）没区别。
   变的只有 dt 的基准，本体形状不动。

2. dt 与 dx 无关，所以这**不是**一条速度曲线。
   移动步的 dt 中位数是 4/2/2ms，原地步也是 4/2/2ms —— 每步花多久和这步
   走没走完全独立。不能写 Δx = v·dt。
   （第一版按 minimum-jerk 钟形曲线写，被数据否掉了：实测速度剖面是
     单调递减、"前 10px 用 25~66ms、最后 10px 用 246~671ms"。）

3. dx∈{0,1} 是 Math.round 的量化产物，不是掷硬币。**这条最容易写错。**
   易盾取的是 round(dragX)，dragX 本身是连续量。所以正确做法是累加一个
   连续位移、记录时再取整；如果每步以概率 p 独立决定走不走，原地步占比
   也能凑到 34%，但连续原地的**长度分布**完全不对：

       模型                    原地%   连续原地分布
       伯努利 p=.65            35%     1步:127  2步:58  3步:16  4步:6  5步:3  6步:1
       累加 mean=.65 sig=.30   33%     1步:193  2步:3
       实测（三条合计）        34%     1步:197  2步:9   3步以上:0

   掷硬币会聚出 5、6 步的长停顿，实测里一次都没有——因为连续位移累加到
   0.5 就必然进位，物理上卡不住那么久。第一版就是栽在这，自检时约一半
   样本最长连续原地到 5 步，而三条实测全是 2 步。

4. 时间全压在末尾的停顿上。
   后 20% 距离的 dt 中位数也才 5ms，46 步却烧了 836ms —— 那几百毫秒是
   0~3 个 100~220ms 的事件空档撑起来的。结构 = 一路飙 + 末尾塞几次停住。

y 的形态同样反直觉：从 0 起步、单调向上漂、只走 ±1、全程只变 2~15 次。
轨迹1 里 y=2 冻了 164 步。**冻住是常态**，别去"让它动起来"。

起点恒定：(4, 0, t0, 1)。钩子挂上时指针已经走了 4px，所以序列里没有
x=0 那一条，第一条恒为 x=4、y=0。
"""
import json
import math
import random

IMAGE_WIDTH = 320
"""背景图自然宽度（px）。"""

IMAGE_WIDTH_CSS = 270
"""背景图的 CSS 宽度。抓包实测：分析/get_live.py 的 CAPTURED 里就是 ('width','270')。"""

SCALE = 0.84375            # == IMAGE_WIDTH_CSS / IMAGE_WIDTH
"""背景图自然像素 -> 滑块 CSS 像素。

270/320 = 0.84375，和 135/160 一致。270 这个数不再是估的 —— 抓包里 width
参数实测就是 270（分析/get_live.py 的 CAPTURED）。

原先这里写着"还没实测标定过……某个 x 值除以 2.7，两种说法对不上"，现在对上了：
参数生成.js 里那条从 v2.28.5 的 core-optimi 扣出来的

    _0x15278a = _0xa8a0c6(_0x3855dc(token, 滑动距离px / 27000 + ''))

27000 = 270 x 100，而 270 正是这里说的图片 CSS 宽。所以"除以 2.7"和
"270/320 的比例"根本不是两种说法，是同一件事的两种单位写法（分子差一个 x100）。

由此得到上报值（推导，未实测）：
    归一化滑动距离 = 自然px * SCALE / 270 = 自然px / 320
SCALE 整个约掉了 —— 也就是直接除以图片自然宽。识别.locate_gap 给的就是自然
像素，所以算归一化值时 SCALE 不用出现，用下面的 normalize() 就行。
"""

FIRST_X = 4
"""首条记录的 x。固定值 —— 起始钩子有延迟，挂上时指针已经走了 4px。"""


def gen_track(target_x, seed=None):
    """生成一条轨迹。

    :param target_x: 终点 x（滑块 CSS 位移），最后一条记录一定是这个值
    :param seed:     固定种子可复现，None 就每次不同
    :return: [[x, y, t, flag], ...]，flag 恒为 1

    每条轨迹都重新随机风格参数。真人的每次滑动都不一样，复用模板等于自曝。
    """
    rnd = random.Random(seed)
    if target_x <= FIRST_X:
        raise ValueError('目标距离 %r 不比起点大，没法生成' % (target_x,))

    # ---- 风格参数：每条轨迹重新摇一遍 ----
    # 节拍决定整体快慢。实测前段 dt 中位 1~4ms（250~700Hz），
    # 快慢的差别基本都在这个数上，本体形态不变。
    # 每步推进的像素数 —— 连续量，记录时再取整（见文件头第 3 条）。
    # 上限别给到 0.75：那样移动步占比会冲到 78%，实测只有 61~68%。
    step_px = rnd.uniform(0.60, 0.68)
    step_sigma = rnd.uniform(0.25, 0.40)
    base_dt = math.exp(rnd.uniform(math.log(0.8), math.log(2.5)))   # 前段节拍，实测中位 1~4ms
    dt_sigma = rnd.uniform(0.25, 0.5)      # 右偏程度，产生少量十几 ms 的慢步
    t0 = rnd.uniform(60, 170)              # 首个事件延迟（实测 66/95/168ms）

    # 停顿：0~3 次，全落在后 20% 距离里（实测 3/2/0 次，位置都在尾段）
    n_stall = rnd.choice((0, 0, 1, 1, 2, 3))
    stalls = sorted((rnd.uniform(0.80, 1.0), rnd.uniform(80, 220))
                    for _ in range(n_stall))

    # 先定"总共花多久"，再倒推尾段要放慢多少 —— 直接摇 dt 的话总时长会飘。
    # 实测每像素 4.8~9.9ms（131px/623ms、103px/895ms、150px/1491ms）。
    # 倍率是随进度线性长上去的（1.0 -> dt_slow），所以全程平均倍率是
    # (1+dt_slow)/2，倒推时要还原这一步，否则总时长只有目标的一半。
    steps_est = (target_x - FIRST_X) / step_px
    want = (target_x - FIRST_X) * rnd.uniform(4.5, 10.5)
    dt_slow = min(8.0, max(1.0, 2.0 * (want - sum(s for _, s in stalls))
                           / (steps_est * base_dt) - 1.0))

    # 过冲回撤：约 1/3 概率。实测三条里只有轨迹2 出现过
    # （冲到 112 停 218ms，再用 9 步 -1 退回 107）。
    overshoot = rnd.randint(3, 6) if rnd.random() < 0.34 else 0

    # y：不是随机游走，是"计划好总漂移量、随机摊到全程"。
    # 单调向上为主，偶尔 -1（实测 dy 取值只有 {-1,0,1}）。
    y_drift = rnd.randint(2, 15)
    y_at = sorted(rnd.random() for _ in range(y_drift))
    y_idx = 0
    y = 0

    def draw_dt(frac):
        """当前进度下的单步耗时（ms）。尾段整体放慢，命中的停顿叠加上去。"""
        dt = math.exp(rnd.normalvariate(math.log(base_dt), dt_sigma))
        dt *= 1.0 + (dt_slow - 1.0) * frac
        while stalls and frac >= stalls[0][0]:
            dt += stalls.pop(0)[1]
        return dt

    peak = target_x + overshoot
    total = peak - FIRST_X
    pts = [(FIRST_X, 0, int(round(t0)), 1)]
    t_f = t0
    x_f = float(FIRST_X)
    x = FIRST_X

    # ---- 主段：一路推进到峰值 ----
    while x < peak:
        # 进度按 x 算（不是按步数）—— 停顿要钉在"距离后 20%"上
        frac = (x - FIRST_X) / total
        if y_idx < y_drift and frac >= y_at[y_idx]:
            # 只在上漂过以后再允许 -1，实测 y 从不为负
            y += -1 if (y > 0 and rnd.random() < 0.12) else 1
            y_idx += 1
        t_f += draw_dt(frac)
        # 连续位移累加，取整时才出现 0/1 的量化步（Math.round 是 floor(v+0.5)）
        x_f += math.exp(rnd.normalvariate(math.log(step_px), step_sigma))
        x = min(int(math.floor(x_f + 0.5)), peak)
        pts.append((x, y, int(round(t_f)), 1))

    # ---- 回撤段：连续后退到 target_x（实测轨迹2：112 -> 107，8 步） ----
    # 这里同样不能掷硬币 —— 每步独立决定退不退，会聚出 5~7 步的长停顿，
    # 和主段一样的毛病（自检时 16 条越界里 14 条来自这段）。
    back_px = step_px * 0.9
    while x > target_x:
        t_f += draw_dt((x - FIRST_X) / total)
        x_f -= math.exp(rnd.normalvariate(math.log(back_px), step_sigma))
        x = max(int(math.floor(x_f + 0.5)), target_x)
        pts.append((x, y, int(round(t_f)), 1))

    pts[-1] = (target_x, y, pts[-1][2], 1)
    return [[a, b, c, d] for a, b, c, d in pts]


def from_gap(gap_x, scale=SCALE, seed=None):
    """直接从 识别.locate_gap 的结果生成。

    :param gap_x: 缺口 x（背景图自然像素）
    :param scale: 自然像素 -> CSS 像素，标定前按 SCALE
    """
    return gen_track(int(round(gap_x * scale)), seed=seed)


def normalize(gap_x):
    """缺口自然像素 -> 上报用的归一化滑动距离（= gap_x / 320）。

    推导见 SCALE 的说明（自然px * 270/320 / 270，两个 270 约掉）。
    **推导值，还没拿真实上报对过** —— 把那条 /27000 的原文扣干净，或者拿一次
    真实上传里的归一化值反除一下，就能钉死。
    """
    return gap_x / float(IMAGE_WIDTH)


def check(pts, verbose=True):
    """拿实测的四条约束回验一遍生成结果。返回问题列表（空 = 通过）。

    这几条不是拍脑袋的，是对着 轨迹{1,2,3}.txt 抄的：
      * 移动步占比 61~68%  -> 放宽到 55~75%
      * 最长连续原地 2 步  -> 放宽到 3 步（累加模型理论上限，留一格余量）
      * dt 中位 1~4ms
      * y 从 0 起步、只走 ±1、漂移量 2~15
      * 总时长 623~1491ms（对应 131~150px），放宽到 400~2500ms
    """
    bad = []
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    ts = [p[2] for p in pts]

    if (xs[0], ys[0]) != (FIRST_X, 0):
        bad.append('起点应为 (%d,0)，实际 (%d,%d)' % (FIRST_X, 0, xs[0], ys[0]))
    if any(p[3] != 1 for p in pts):
        bad.append('flag 出现非 1 的值')
    if any(ts[i] < ts[i - 1] for i in range(1, len(ts))):
        bad.append('t 不是单调不减')

    dx = [xs[i] - xs[i - 1] for i in range(1, len(xs))]
    mv = sum(1 for d in dx if d > 0) / float(len(dx))
    if not 0.55 <= mv <= 0.75:
        bad.append('移动步占比 %.0f%% 出界 (目标 55~75%%)' % (mv * 100))

    hold = cur = 0
    for d in dx:
        cur = cur + 1 if d == 0 else 0
        hold = max(hold, cur)
    if hold > 3:
        bad.append('最长连续原地 %d 步 (目标 <=3)' % hold)

    span = ts[-1] - ts[0]
    if not 400 <= span <= 2500:
        bad.append('总时长 %dms 出界 (目标 400~2500)' % span)

    dt = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
    med = sorted(dt)[len(dt) // 2]
    if not 0 <= med <= 6:
        bad.append('dt 中位 %dms 出界 (目标 0~6)' % med)

    dy = set(ys[i] - ys[i - 1] for i in range(1, len(ys)))
    if not dy <= {-1, 0, 1}:
        bad.append('y 单步变化出现 %s (目标只允许 -1/0/1)' % sorted(dy - {-1, 0, 1}))
    if not 0 <= ys[-1] <= 20:
        bad.append('y 总漂移 %d 出界 (目标 0~20)' % ys[-1])

    if verbose:
        print('n=%d  x %d->%d  y %d->%d  t %d->%d  '
              '移动步 %.0f%%  最长原地 %d  回退 %d 步'
              % (len(pts), xs[0], xs[-1], ys[0], ys[-1], ts[0], ts[-1],
                 mv * 100, hold, sum(1 for d in dx if d < 0)))
        print('   ' + ('通过' if not bad else '不通过: ' + '; '.join(bad)))
    return bad


OBSERVED = [
    ([4, -2, 101, 1], 'rZm9xwEvic7+xp33'),
    ([4, -2, 104, 1], 'rZm9xwEvic9+xp33'),
    ([5, -2, 107, 1], 'rIm9xwEvicO+xp33'),
    ([5, -2, 109, 1], 'rIm9xwEvicJ+xp33'),
    ([6, -2, 112, 1], 'rXm9xwEviAg+xp33'),
    ([7, -2, 114, 1], 'rrm9xwEviA9+xp33'),
    ([7, -2, 116, 1], 'rrm9xwEviAv+xp33'),
    ([7, -3, 117, 1], 'rrm9xeEviAO+xp33'),
    ([8, -3, 118, 1], '\\Zm9xeEviAW+xp33'),
    ([9, -3, 123, 1], '\\Im9xeEvii/+xp33'),
    ([9, -3, 124, 1], '\\Im9xeEvii9+xp33'),
    ([10, -3, 126, 1], 'vEzjgp7ziAg\\ggN3'),
]
"""实测抓到的一组明文->密文对照（12 条，同一次拖动的前 12 个事件）。

按 4/4/4/4 切这 16 个字符，第 1 组只随 x 变（x=4->rZm9 出现两次、5->rIm9
两次、7->rrm9 三次、9->\\Im9 两次，全一致），第 2 组的第 2 个字符只在 y
翻号那一行变（xwEv -> xeEv）。所以 [x | y | t | flag] 的切分基本成立。

两个还没解释的：最后一行 [10,-3,126,1] 整条都不搭（x 9->10 就全变了，像
进位），而且字母表里有反斜杠、不是标准 base64，是张自定义表。
"""


def gen_batch(count, distance, seed0=0):
    """批量生成，返回 [{id, target_x, seed, plain}, ...]。种子连续，可复现。"""
    return [{'id': 's%d-%03d' % (distance, i), 'target_x': distance,
             'seed': seed0 + i, 'plain': gen_track(distance, seed=seed0 + i)}
            for i in range(count)]


def probes(base=(4, 0, 100, 1)):
    """单字段探针 —— 比随机轨迹更适合扣算法。

    一次只动一个字段、只动一格，然后把密文和基准逐字符 diff，哪几位是哪个
    字段的、进不进位，一眼就看出来。随机轨迹做不到这个：同时动四个字段，
    密文整条都变，分不清谁影响谁。

    特意包含了 9->10 / 99->100 这种**位数变化**，以及 y 过零、t 跨量级 ——
    对照表里 [10,-3,126,1] 那行整条都变，很可能就是位数/进位在起作用。
    """
    bx, by, bt, bf = base
    out = [{'id': 'base', 'plain': list(base),
            'why': '基准，其余每条都只跟它差一格'}]
    sweeps = [
        ('x', 0, lambda v: (v, by, bt, bf), [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                                             9, 10, 11, 15, 16, 63, 64, 65, 100]),
        ('y', 1, lambda v: (bx, v, bt, bf), [-5, -3, -2, -1, 0, 1, 2, 3, 5, 10, 20]),
        ('t', 2, lambda v: (bx, by, v, bf), [0, 1, 9, 10, 63, 64, 99, 100, 101,
                                             255, 256, 999, 1000, 1023, 1024,
                                             4095, 4096, 16383, 16384, 65535]),
        ('flag', 3, lambda v: (bx, by, bt, v), [0, 1, 2, 3]),
    ]
    for name, _pos, mk, vals in sweeps:
        for v in vals:
            plain = list(mk(v))
            tag = 'base' if plain == list(base) else '%s=%d' % (name, v)
            out.append({'id': '%s-%s' % (name, v), 'plain': plain, 'why': tag})
    return out


def dump_json(path, generated=None, observed=None, probes_=None):
    """写语料 JSON。

    结构上给每条都留了 cipher 空位：等把 _0x564a9f 扣下来，按 id 回填密文
    就能直接做对照。注意加密入参是 `arr + ''`（逗号拼接的字符串），不是
    数组本身，所以 plain 和 plain_str 两条都存，别只存数组。
    """
    def with_str(item):
        """observed/probes 是单条记录，generated 是一整条轨迹，两种形状都要接。"""
        item = dict(item)
        plain = item['plain']
        if plain and isinstance(plain[0], (list, tuple)):
            item['plain_str'] = [','.join(str(v) for v in rec) for rec in plain]
        else:
            item['plain_str'] = ','.join(str(v) for v in plain)
        item.setdefault('cipher', None)
        return item

    doc = {
        '_note': '易盾滑块轨迹语料。plain 是明文轨迹，plain_str 等价于 JS 的 '
                 '`arr + ""`，也就是真正喂给 _0x564a9f 的字符串。'
                 'cipher 留空，抓到以后按 id 回填。',
        'observed': [with_str({'id': 'obs-%02d' % i, 'plain': list(p),
                               'cipher': c, 'why': '实测抓包'})
                     for i, (p, c) in enumerate(observed or OBSERVED)],
        'generated': [with_str(s) for s in (generated or [])],
        'probes': [with_str(s) for s in (probes_ or [])],
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return doc


if __name__ == '__main__':
    # 自检：三种距离各生成 200 条，逐条回验
    for target in (107, 135, 154):
        print('--- 目标 x = %d ---' % target)
        fails = 0
        for s in range(200):
            if check(gen_track(target, seed=s), verbose=False):
                fails += 1
        check(gen_track(target, seed=0))
        print('   200 条里 %d 条越界' % fails)

    demo = gen_track(135, seed=7)
    print('\n示例 (target_x=135, n=%d):' % len(demo))
    for p in demo[:6] + [['...']] + demo[-6:]:
        print('   ', p)

    gen = []
    for d in (80, 110, 135, 170, 210):
        gen += gen_batch(4, d, seed0=d)
    doc = dump_json('轨迹语料.json', gen, probes_=probes())
    print('\n已写出 轨迹语料.json：实测 %d 条 / 生成 %d 条 / 探针 %d 条'
          % (len(doc['observed']), len(doc['generated']), len(doc['probes'])))
