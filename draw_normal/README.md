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

---

### 大致原理

这里仅介绍代码的大致结构和原理，具体细节还得看源码


---

