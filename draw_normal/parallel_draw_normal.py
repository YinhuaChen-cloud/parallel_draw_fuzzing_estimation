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

############################################### 0. 配置部分         ##################################################
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

############################################### 一些常用常数、函数的定义(尽量别修改) ##############################
SPLIT_UNIT = 1
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量

# 获取 basedir 下的子目录列表
def getsubdir(basedir):
    subdirs = [d for d in os.listdir(basedir) 
        if os.path.isdir(os.path.join(basedir, d)) and not d.startswith('.') ]
    return sorted(subdirs)

######################################## 1. 验证 fuzzing result 是否有异常 ##################################################
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

############################################### 2. 并行读取绘图所需数据 (plot_data) ##################################################

# 一个全局变量，被所有并行任务共享，标识已经完成的任务数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

# 被并行执行的函数 --------------------------------------------------------------- start
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME, task_count):
    # 当前这个 PROGRAM-FUZZER-TIME 所对应的 plot_data 文件路径
    plot_data_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/default/plot_data"
    # plot_data 是 csv 格式的，所以我们可以使用 pandas.DataFrame 的 csv API 读取它
    df = pd.read_csv(plot_data_path)
    # 把所有列表的首尾空白字符去掉
    df.columns = df.columns.str.strip()

    # 打印信息，表示这个数据收集任务已完成
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME, df)
# 被并行执行的函数 --------------------------------------------------------------- end

# 获取当前机器上的 CPU cores 总数，方便后续并行操作
num_cores = multiprocessing.cpu_count()
print(f'CPU 核心数量: {num_cores}')
sys.stdout.flush()

# 创建一个进程池，池中进程的数量等于 CPU 核心数量
pool = multiprocessing.Pool(num_cores)

# 储存收集数据结果的队列
results = []

# 任务数计数器，也可以叫任务序号计数器
task_count = 0

# 为每一个 program-fuzzer-repeat_time 收集 plot_data 数据
for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
        # 收集这个 PROGRAM-FUZZER 的所有 REPEAT_times 的 plot_data 数据

        # 找到包含当前 PROGRAM 的 TARGETS
        for TARGET in TARGETS:
            path = FUZZER + "/" + TARGET
            thePROGRAMS = getsubdir(path)
            for thePROGRAM in thePROGRAMS:
                if thePROGRAM != PROGRAM:
                    continue

                # 验证 fuzzing result 的 repeat_times 是否和我们的 0.配置部分 一致
                path = FUZZER + "/" + TARGET + "/" + PROGRAM
                TIMES = getsubdir(path)
                assert(len(TIMES) == REPEAT)
                for TIME in TIMES:
                    assert(int(TIME) < REPEAT)

                # 分配一个 CPU cores，让它收集当前 PROGRAM-FUZZER-TIME 的 plot_data 信息，结果存放于 results 列表
                for TIME in TIMES:
                    result = pool.apply_async(collect_data_worker, (FUZZER, TARGET, PROGRAM, TIME, task_count))
                    task_count += 1
                    results.append(result)

# 打印看看一共有多少个并行任务在运行
print(f"================== There are {len(results)} data collect tasks in total ==================")
sys.stdout.flush()

# 等待所有并行任务结束
for result in results:
    result.wait()

############################################### 3. 统计各程序 max_execs   ##################################################
# 这一部分的目的，是为了确认各个 PROGRAM 的执行次数横轴图的最大执行次数
# 因为不同 FUZZERS 执行速率不一样，所以哪怕运行相同的时间，最后产生的最大执行次数可能差很多
# 我这里是取执行速率最慢的 FUZZERS 的最大执行次数，作为绘图的最大执行次数

# 这个字典的 key 是 PROGRAM, value 是该 PROGRAM 在所有 FUZZERS 中最小的 max_execs
max_execs_dict = {}

# 统计每个 PROGRAM 在所有 FUZZERS 中最小的 max_execs，存放于 max_execs_dict 中
for PROGRAM in PROGRAMS:
    # 找到当前 PROGRAM 在所有 FUZZERS 中最小的 max_execs
    max_execs = float('inf')
    for FUZZER in FUZZERS:
        # 在 results 列表中找到 当前 PROGRAM-FUZZER 的所有数据，存放于 dfs 列表中
        dfs = []
        for result in results:
            fuzz_result = result.get()
            if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                continue
            dfs.append(fuzz_result[4])
        # 收集完后，一共能收集到 REPEAT 个 df
        assert(len(dfs) == REPEAT)
        # 在 dfs 列表中找到最小的 max_execs
        for df in dfs:
            if df["total_execs"].max() < max_execs:
                max_execs = df["total_execs"].max() 
    # 把这个 PROGRAM 在所有实验中的最小的 max_execs 存放于 max_execs_dict 字典中
    max_execs_dict[PROGRAM] = max_execs

# TODO: check 到这里

############################################### 额外：定义绘图函数   ##################################################
# name: 决定 y 轴和图的名字
# colname: 关心的那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？
def draw_time(name: str, colname: str, accumulate: bool):
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，获取 dfs
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[4])
            assert(len(dfs) == REPEAT)
            # CHANGE: 绘制其它图片，提取的数据要变化
            # 处理 dfs 的数据，提取出 crash-time 数组，总共 REPEAT 个
            slot_list = []
            for df in dfs:
                slot = [0] * SPLIT_NUM
                # 按照相应单位，把 df 中的数据转移到数组上
                # 先给 df 排序
                df = df.sort_values("# relative_time")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    time_s = int(row["# relative_time"])
                    k = math.ceil(time_s / 60)
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
                # 检查一下，看看是否有中间为 0 的情况，若有，补上
                assert(slot[0] == 0)
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            assert(len(slot_list) == REPEAT)
            # CHANGE: 绘制其它图片，对小数点的处理方式可能不一样
            # 求平均，改成向上取整
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
                slot_avg[i] = math.ceil(slot_avg[i])

            # CHANGE: 绘制其它图片，这里的 x 轴可能不一样
            # 开始绘图
            x = [ (i/60) for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # CHANGE: 绘制其它图片，这里的标题可能不一样
        # 添加标题和标签
        # 注意：edges 最好使用 min 作为横轴单位！！！
        plt.title(PROGRAM + " " + name + '-time graph')
        plt.xlabel('time(h)')
        plt.ylabel('# ' + name)
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig(name + '_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        print("finish drawing " + name + "_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()

        plt.close()  # 关闭图形

    print("============================= finish drawing " + name + "_time graph part =============================")
    sys.stdout.flush()

# name: 决定 y 轴和图的名字
# colname: 关心的那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？
def draw_execs(name: str, colname: str, accumulate: bool):
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形
        # 获取这个程序的 max_execs，计算 execs_unit
        max_execs = max_execs_dict[PROGRAM]
        execs_unit = (max_execs / int(TOTAL_TIME / SPLIT_UNIT))

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，获取 dfs
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[4])
            assert(len(dfs) == REPEAT)
            # CHANGE: 绘制其它图片，提取的数据要变化
            # 处理 dfs 的数据，提取出 crash-execs 数组，总共 REPEAT 个
            slot_list = []
            for df in dfs:
                slot = [0] * SPLIT_NUM
                # 按照相应单位，把 df 中的数据转移到数组上
                # 先给 df 排序
                df = df.sort_values("total_execs")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    execs = int(row["total_execs"])
                    k = math.ceil(execs / execs_unit)
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
                # 检查一下，看看是否有中间为 0 的情况，若有，补上
                assert(slot[0] == 0)
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            assert(len(slot_list) == REPEAT)
            # CHANGE: 绘制其它图片，对小数点的处理方式可能不一样
            # 求平均，改成向上取整
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
                slot_avg[i] = math.ceil(slot_avg[i])

            # CHANGE: 绘制其它图片，这里的 x 轴可能不一样
            # 开始绘图
            x = [ i*execs_unit for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # CHANGE: 绘制其它图片，这里的标题可能不一样
        # 添加标题和标签
        # 注意：edges 最好使用 min 作为横轴单位！！！
        plt.title(PROGRAM + " " + name + '-execs graph')
        plt.xlabel('# execs')
        plt.ylabel('# ' + name)
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig(name + '_execs_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        print("finish drawing " + name + "_execs_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()

        plt.close()  # 关闭图形

    print("============================= finish drawing " + name + "_execs graph part =============================")
    sys.stdout.flush()

############################################### 4. 绘制 crash_time   ##################################################
if draw_configure["crash_time"]:
    draw_time("crash", "saved_crashes", True)

############################################### 5. 绘制 crash_execs  ##################################################
if draw_configure["crash_execs"]:
    draw_execs("crash", "saved_crashes", True)

############################################### 6. 绘制 seed_time    ##################################################
if draw_configure["seed_time"]:
    draw_time("seed", "corpus_count", True)

############################################### 7. 绘制 seed_execs   ##################################################
if draw_configure["seed_execs"]:
    draw_execs("seed", "corpus_count", True)

############################################### 10. 绘制 Throughput  ##################################################
if draw_configure["throughput_time"]:
    draw_time("execs_per_sec", "execs_per_sec", False)

############################################### 要结束了             ##################################################
pool.close()
pool.join()
exit(0)  




