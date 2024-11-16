# Draw_normal 使用方法

用于绘制 crash, seed 的时间横轴图以及执行次数(execs)横轴图。同时会绘制 Throughput。

python 文件为 parallel_draw_normal.py

---

### 使用方法

使用之前，需要对 parallel_draw_normal.py 进行配置
```python
########### 0. 配置部分 ###########  
TOTAL_TIME = 12 * 60 # 单位分钟
FUZZERS = ["aflplusplus", "nopathreduction"]
TARGETS = ["base64", "md5sum", "uniq", "who", "libpng", "libsndfile", "php", "sqlite3", "lua", "libxml2", "libtiff", "openssl"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# 重复次数
REPEAT=1
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_all"
# 决定绘制哪些图，不绘制哪些图
draw_configure = {
    "crash_time"     : True,
    "crash_execs"    : True,
    "seed_time"      : True,
    "seed_execs"     : True,
    "throughput_time": True,
}
```

TOTAL_TIME: 表示你这次跑的 fuzzing 实验的总时间 (单位：分钟)

FUZZERS: 一个列表，表示这次 fuzzing 使用了哪些 fuzzers

TARGETS: 一个列表，表示这次 fuzzing 参与的 TARGETS (PUTs) 有哪些

WORKDIR: 表示运行 parallel_draw_normal.py 脚本的根目录名字叫什么

REPEAT: 表示每个 fuzzer-target 实验要重复的次数

SPECIFIC_SUFFIX: 产生的图片文件名后缀

draw_configure: 一个字典，标 True 标识要绘制这种类型的图片，标 False 标识不绘制这种类型的图片

配置完毕后，就可以运行脚本

假设我们用来跑 fuzzing 实验的 experiments architecture 是基于 MAGMA benchmark 的，那么运行完实验后，在 \<magma-root-dir\>/tools/captaion 下应该有一个 workdir 目录，这个目录存放着 fuzzing results。如果是我修改过的版本，那么 fuzzing 结果存在于 workdir/cache 文件夹内。

运行方法如下：
```bash
cp parallel_draw_normal.py \<magma-root-dir\>/tools/captaion/workdir/cache
cd \<magma-root-dir\>/tools/captaion/workdir/cache
python3 parallel_draw_normal.py 
```

日志打印完毕后，应该在 \<magma-root-dir\>/tools/captaion/workdir/cache 目录下能看到一堆图片文件

---

### 代码结构和大致原理

这里仅介绍代码结构和大致原理，具体细节还得看源码

代码结构分为下面几个

0.配置部分，这部分根据 “使用方法” 一节去配置就可以了

1.验证 fuzzing result 是否有异常。这里做的事情包括：
- 执行脚本的目录名是否和 WORKDIR 一致
- 配置中的 FUZZERS 是否在 fuzzing results 中存在
- 配置中的 TARGETS 是否在 fuzzing results 中存在
- fuzzing results 中的 PROGRAMS 是否齐全且一致

这一部分其实就是验证 fuzzing results 是否有异常、是否和配置有出入

2.并行读取绘图所需数据(plot_data): 这部分是并行读取 plot_data 数据

3.统计各程序 max_execs：这一部分的目的，是为了确认各个 PROGRAM 的执行次数横轴图的最大执行次数。因为不同 FUZZER 执行速率不一样，所以哪怕运行相同的时间，最后产生的最大执行次数可能差很多。我这里是取执行速率最慢的 FUZZER 的最大执行次数，作为绘图的最大执行次数

4.定义绘图函数：大部分图片的绘制过程是可以复用的，所以先定义绘图函数，后续在绘图的时候调用这些函数，可以提高代码简洁和可维护性

5-9.使用 4 定义的绘图函数，以及 0 的配置进行绘图。

draw_time 和 draw_execs 的第一个参数是 y 轴的名字，第二个参数是相应数据在 plot_data 中的属性名，第三个参数表示这是否是 “积累属性”。关于积累属性是啥，可以看看 parallel_draw_normal.py 中 draw_time 和 draw_execs 的函数定义，这里面对于 accumulate 参数的解释写得很清楚。

10.退出：关闭并行任务池子，退出整个脚本

---

