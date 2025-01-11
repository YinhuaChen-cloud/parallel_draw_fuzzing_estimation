import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import csv
import pandas as pd
import math

############################################### 0. 配置部分         ################################################## 完成
TOTAL_TIME = 2160 # 单位分钟
FUZZERS = ["aflplusplus", "fixversion"]
TARGETS = ["base64", "libpng", "libsndfile", "libtiff", "libxml2", "md5sum", "php", "sqlite3", "uniq", "who"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# 重复次数
REPEAT=1
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_all"
# 决定绘制哪些图，不绘制哪些图
draw_configure = {
    "crash_time": True,
    "crash_execs": True,
    "seed_time": True,
    "seed_execs": True,
}

# 如果开启了并行 fuzz，那么 Master-Slave 机制下的 IDs 列表
PARALLEL_IDS = ["Master", "Slave1", "Slave2"]

############################################### 一些常用常数、函数的定义(尽量别修改) ############################## 完成
SPLIT_UNIT = 1
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量

# 获取 basedir 下的子目录列表
def getsubdir(basedir):
    subdirs = [d for d in os.listdir(basedir) 
        if os.path.isdir(os.path.join(basedir, d)) and not d.startswith('.') ]
    return sorted(subdirs)

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### 完成 
# 首先验证 WORKDIR是否正确
current_directory = os.getcwd()
directory_name = os.path.basename(current_directory)
assert(directory_name == WORKDIR)

# 验证配置中的 FUZZERS，是否在 fuzzing result 中都存在
FUZZERS_real = getsubdir(current_directory)
for fuzzer in FUZZERS:
    assert(fuzzer in FUZZERS_real)

# 验证配置中的 TARGETS 是否在所有 FUZZERS 里都存在
TARGETS_list = []
for FUZZER in FUZZERS:
    TARGETS_list.append(getsubdir(FUZZER))

for i in range(len(TARGETS_list)):
    for target in TARGETS:
        assert(target in TARGETS_list[i])

# 验证所有的 TARGETS，是否 PROGRAMS 齐全
PROGRAMS_list = []

for FUZZER in FUZZERS:
    the_PROGRAMS = []
    for TARGET in TARGETS:
        path = FUZZER + "/" + TARGET
        the_PROGRAMS.append(getsubdir(path))
    the_PROGRAMS = [ item for sublist in the_PROGRAMS for item in sublist ]
    PROGRAMS_list.append(the_PROGRAMS)

for i in range(len(PROGRAMS_list)):
    assert(PROGRAMS_list[i] == PROGRAMS_list[0])

PROGRAMS = PROGRAMS_list[0]

############################################### 2. 对所有文件 ############################### 


sys.exit(0)

############################################### 3. 定义绘图函数   ################################################## 
# name: 决定 y轴 和图的名字
# colname: plot_data 中和 y轴 相应那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？ (crash, seed 属于积累属性, Throughput 不属于)
# 或者说，种子数量、crash数量、bug 数量这些是可以积累的，但是 “速度” 是不可以积累的
# 路程是可以积累的，速度是不能积累的。学习的知识是可以积累的，学习的速度是不能积累的
# 这就是 “积累” 属性
def draw_time(name: str, colname: str, accumulate: bool):
    # 每一个 PROGRAM 绘制一张图 (FUZZERS 是这张图上的 legend)
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，储存在 dfs 列表中
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[5])
            # 验证 REPEAT 是否和 dfs 收集到的数量一致
            assert(len(dfs) == (REPEAT * len(PARALLEL_IDS)))
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME-parallel_id 的 plot_data，可以绘制成一条线
            # 我们要对这些 df 的值取平均
            # slot_list 就是用来存放绘图数据数组的列表
            slot_list = []
            for df in dfs:
                # 用来绘图的数据数组
                slot = [0] * SPLIT_NUM
                # 因为是 draw_time 先给 df 按照时间排序排序
                df = df.sort_values("# relative_time")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    # 取得这一行的时间(单位：秒)
                    time_s = int(row["# relative_time"])
                    # 把时间转为分钟，随后放入 slot 中相应的位置
                    k = math.ceil(time_s / 60)
                    # 部分实验可能会运行超过规定的时间，我们把超过规定时间的数据忽略掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # 因为我们计算 k 是向上取整，所以元素0必须为0
                assert(slot[0] == 0)
                # 如果这个属性是 “积累属性”，那么就需要填补 slot 中为 0 的部分
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            # 验证，slot_list 的长度必须等于 REPEAT x len(PARALLEL_IDS)
            assert(len(slot_list) == (REPEAT * len(PARALLEL_IDS)))
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT * len(PARALLEL_IDS)):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= (REPEAT * len(PARALLEL_IDS))
                slot_avg[i] = math.ceil(slot_avg[i])

            # 有了 slot_avg 就能绘图了
            # 开始绘图
            # x 轴以小时(h) 为单位，我们的 slot_avg 每一个下标都是分钟 min，所以这里要除以 60
            x = [ (i/60) for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 这个 PROPGRAM 绘制完毕后，要命名
        # 设置标题
        plt.title(PROGRAM + " " + name + '-time graph')
        # 设置 x 轴
        plt.xlabel('time(h)')
        # 设置 y 轴
        plt.ylabel('# ' + name)
        # 设置文件名和文件类型 (png, svg, pdf ....)
        plt.savefig(name + '_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg') 
        # 打印日志标识成功绘制这个图片
        print("finish drawing " + name + "_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()
        # 关闭图形，节约内存
        plt.close()  

    # 打印日志：成功绘制完某一类型的图片
    print("============================= finish drawing " + name + "_time graph part =============================")
    sys.stdout.flush()

############################################### 4. 绘制 相关 图    ################################################## 完成

if draw_configure["crash_time"]:
    draw_time("crash", "saved_crashes", True)

if draw_configure["crash_execs"]:
    draw_execs("crash", "saved_crashes", True)

if draw_configure["seed_time"]:
    draw_time("seed", "corpus_count", True)

if draw_configure["seed_execs"]:
    draw_execs("seed", "corpus_count", True)

############################################### 5. 要结束了                   ################################################## 完成   
# 关闭并行任务池子、退出
pool.close()
pool.join()
exit(0)  



    # crash_time_slot = [0] * SPLIT_NUM
    # path = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    # files = getfiles(path)
    # for crash_file in files:
    #     matches = re.findall(r"time:(\d+)", crash_file)
    #     assert(len(matches) < 2)
    #     if matches:
    #         crash_time = int(matches[0])
    #         # 先转为秒
    #         crash_time /= 1000
    #         # 再转为分
    #         crash_time /= 60
    #         # 再转为小时
    #         crash_time /= 60
    #         # 向下取整
    #         crash_time = int(crash_time)
    #         # 如果时间戳没有超过配置最大值，那么记录数据
    #         if crash_time < SPLIT_NUM:
    #             crash_time_slot[crash_time] += 1
    # # 从增量数组转为存量数组
    # for i in range(SPLIT_NUM-1):
    #     crash_time_slot[i+1] += crash_time_slot[i]
    # # 打印表示目前任务已完成(需要加锁)
    # global finished_tasks
    # with finished_tasks.get_lock():
    #     finished_tasks.value += 1
    #     print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
    #     sys.stdout.flush()
    # return (FUZZER, TARGET, thePROGRAM, TIME, crash_time_slot)