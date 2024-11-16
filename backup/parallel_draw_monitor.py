import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess
import csv
import pandas as pd
import math

############################################### 0. 配置部分         ##################################################
TOTAL_TIME = 48 * 60 # 单位分钟
SPLIT_UNIT = 1  # 每隔 1 分钟
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量
# # 比较所有 fuzzers 的情况
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_empty_path_k_2", "path_fuzzer_empty_path_k_4", "path_fuzzer_empty_path_k_8", \
    # "path_fuzzer_full_path_k_1", "path_fuzzer_full_path_k_2", "path_fuzzer_full_path_k_4", "path_fuzzer_full_path_k_8"]
# 只比较 k=1 和 AFL++ 的情况
FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_full_path_k_1"]
TARGETS = ["php", "libsndfile", "libpng", "libtiff", "libxml2", "sqlite3", "lua"]
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path", "path_fuzzer_full_path", "cov_trans_fuzzer_empty_path", "cov_trans_fuzzer_full_path"]
# TARGETS = ["base64", "md5sum", "uniq", "who"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# WORKDIR = "workdir_1d_REPEAT4_LAVAM"
# 重复次数
REPEAT=2
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_only1"

############################################### 1. 一些函数的定义    ##################################################
# 定义获取子目录的函数
def getsubdir(basedir):
    subdirs = [d for d in os.listdir(basedir) 
        if os.path.isdir(os.path.join(basedir, d)) and not d.startswith('.') ]
    return sorted(subdirs)

# 定义获取文件的函数
def getfiles(basedir):
    files = [f for f in os.listdir(basedir) 
        if os.path.isfile(os.path.join(basedir, f)) and not f.startswith('.')]
    return sorted(files)

# 判断一个文件是否包含非空白字符
def containsNonEmpty(filename):
    with open(filename, 'r') as file:
        content = file.read()
        has_non_blank = any(char.strip() for char in content)
    return has_non_blank

############################################### 2. 验证部分         ##################################################
# 首先验证 WORKDIR
current_directory = os.getcwd()
directory_name = os.path.basename(current_directory)
assert(directory_name == WORKDIR)

# 验证 FUZZERS 是否都存在
FUZZERS_real = getsubdir(current_directory)
for fuzzer in FUZZERS:
    assert(fuzzer in FUZZERS_real)

# 验证 TARGETS 是否在所有 FUZZERS 里都存在
TARGETS_list = []
for FUZZER in FUZZERS:
    TARGETS_list.append(getsubdir(FUZZER))

for i in range(len(TARGETS_list)):
    for target in TARGETS:
        assert(target in TARGETS_list[i])

# 验证是否所有 PROGRAMS 都一样，同时获取 PROGRAMS 列表
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

############################################### 3. 读取所有 monitor 总结 bug_time 数组 ##################################################
# 一个全局变量，被 multiprocessing 所有进程共享，可以加锁
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

# 返回 bug_time 数组
def collect_monitor_worker(FUZZER, TARGET, PROGRAM, TIME, task_count):
    # 先定义 bug_time slot
    slot = [0] * SPLIT_NUM
    # monitor_dir 是 monitor 文件夹所在的位置
    monitor_dir = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/monitor"
    # 获取 monitor_list 按从小到大的顺序
    monitor_files = getfiles(monitor_dir)
    # 如果文件中有 tmp，那么扔掉它
    if "tmp" in monitor_files:
        monitor_files.remove("tmp")

    monitor_list = list(map(int, monitor_files))
    monitor_list = sorted(monitor_list)
    
    # 看看是否排序成功
    for i in range(len(monitor_list) - 1):
        assert(monitor_list[i+1] > monitor_list[i])

    for monitor_num in monitor_list:
        monitor_path = monitor_dir + "/" + str(monitor_num)
        if containsNonEmpty(monitor_path):
            df = pd.read_csv(monitor_path)
            df = df.loc[:, df.columns.str.contains('_T')]
            assert(len(df) == 1)
            # 统计这个时间触发的 bug 数量
            bug_count = (df > 0).sum().sum()
            # 计算分钟
            k = math.ceil(monitor_num / 60)
            if k < SPLIT_NUM:
                slot[k] = bug_count
                
    # 检查一下，看看是否有中间为 0 的情况，若有，补上
    assert(slot[0] == 0)
    for i in range(SPLIT_NUM):
        if i > 0 and slot[i] == 0:
            slot[i] = slot[i-1]

    # 打印表示目前任务已完成(需要加锁)
    # global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame
    return (FUZZER, TARGET, PROGRAM, TIME, slot)

############################################### 3. 读取所有 monitor 总结 bug_time 数组 ##################################################
# 获取 CPU cores 总数
num_cores = multiprocessing.cpu_count()
print(f'CPU 核心数量: {num_cores}')
sys.stdout.flush()

# 创建一个进程池，池中进程的数量等于 CPU 核心数量
pool = multiprocessing.Pool(num_cores)
# 储存结果的队列
bug_time_results = []
# 创建任务列表，任务数量 = len(PROGRAMS) * REPEAT_TIMES
# 任务ID为：FUZZER + TARGET + PROGRAM + REPEAT
# 任务数计数器，也可以叫任务序号计数器
task_count = 0
for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
        # 已知这些 TARGETS 里有且仅有一个 TARGET 包含目标 PROGRAM
        for TARGET in TARGETS:

            path = FUZZER + "/" + TARGET
            thePROGRAMS = getsubdir(path)
            for thePROGRAM in thePROGRAMS:
                if thePROGRAM != PROGRAM:
                    continue
                # 运行到这里，说明找到正确的 TARGET 了
                path = FUZZER + "/" + TARGET + "/" + PROGRAM
                TIMES = getsubdir(path)
                assert(len(TIMES) == REPEAT)

                for TIME in TIMES:
                    assert(int(TIME) < REPEAT)

                for TIME in TIMES:
                    result = pool.apply_async(collect_monitor_worker, (FUZZER, TARGET, PROGRAM, TIME, task_count))
                    task_count += 1
                    bug_time_results.append(result)

# 等待所有异步任务完成
print(f"================== There are {len(bug_time_results)} data collect tasks in total ==================")
sys.stdout.flush()
for result in bug_time_results:
    result.wait()

############################################### 4. 绘制 bug_time 图   ##################################################
bug_time_dict = {}
for PROGRAM in PROGRAMS:

    plt.figure()  # 创建一个新的图形

    for FUZZER in FUZZERS:
        # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数组，随后求平均
        count = 0
        slot_list = [[] for _ in range(REPEAT)]
        for result in bug_time_results:
            fuzz_result = result.get()
            if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                continue
            slot_list[count] = fuzz_result[4]
            count += 1
        assert(count == REPEAT)
        # 求平均，向上取整
        slot_avg = [0] * SPLIT_NUM
        for i in range(SPLIT_NUM):
            for k in range(REPEAT):
                slot_avg[i] += slot_list[k][i]
            slot_avg[i] /= REPEAT
            slot_avg[i] = math.ceil(slot_avg[i])
        # 开始绘图  CHANGE:
        x = [ (i/60) for i in range(SPLIT_NUM) ]
        y = slot_avg
        bug_time_dict[PROGRAM + FUZZER] = slot_avg
        # 绘制图形
        plt.plot(x, y, linestyle='-', label=FUZZER) 
        # 添加图例
        plt.legend()

    # CHANGE: 绘制其它图片，这里的标题可能不一样
    # 添加标题和标签
    # 注意：edges 最好使用 min 作为横轴单位！！！
    plt.title(PROGRAM + " bug-time graph")
    plt.xlabel('time(h)')
    plt.ylabel('# bug')
    # 保存图形为文件: 每个 PROGRAM 画一张图
    plt.savefig('bug_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
    print("finish drawing bug_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
    sys.stdout.flush()

    plt.close()  # 关闭图形

print("============================= finish drawing bug_time graph part =============================")
sys.stdout.flush()

# 要结束了
pool.close()
pool.join()

############################################### 4. 读取所有 plot_data ##################################################
# 一个全局变量，被 multiprocessing 所有进程共享，可以加锁
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

"""用来收集 plot_data 的工作函数 --- start"""
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME, task_count):
    # 使用 pandas.DataFrame 读取 plot_data 文件
    plot_data_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/default/plot_data"
    df = pd.read_csv(plot_data_path)
    # 对所有列名进行 strip() 处理
    df.columns = df.columns.str.strip()

    # 打印表示目前任务已完成(需要加锁)
    # global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame
    return (FUZZER, TARGET, PROGRAM, TIME, df)
"""用来收集 plot_data 的工作函数 --- end"""

# 获取 CPU cores 总数
num_cores = multiprocessing.cpu_count()
print(f'CPU 核心数量: {num_cores}')
sys.stdout.flush()

# 创建一个进程池，池中进程的数量等于 CPU 核心数量
pool = multiprocessing.Pool(num_cores)
# 储存结果的队列
results = []
# 创建任务列表，任务数量 = len(PROGRAMS) * REPEAT_TIMES
# 任务ID为：FUZZER + TARGET + PROGRAM + REPEAT
# 任务数计数器，也可以叫任务序号计数器
task_count = 0
for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
        # 已知这些 TARGETS 里有且仅有一个 TARGET 包含目标 PROGRAM
        for TARGET in TARGETS:

            path = FUZZER + "/" + TARGET
            thePROGRAMS = getsubdir(path)
            for thePROGRAM in thePROGRAMS:
                if thePROGRAM != PROGRAM:
                    continue
                # 运行到这里，说明找到正确的 TARGET 了
                path = FUZZER + "/" + TARGET + "/" + PROGRAM
                TIMES = getsubdir(path)
                assert(len(TIMES) == REPEAT)

                for TIME in TIMES:
                    assert(int(TIME) < REPEAT)

                for TIME in TIMES:
                    result = pool.apply_async(collect_data_worker, (FUZZER, TARGET, PROGRAM, TIME, task_count))
                    task_count += 1
                    results.append(result)

# 等待所有异步任务完成
print(f"================== There are {len(results)} data collect tasks in total ==================")
sys.stdout.flush()
for result in results:
    result.wait()

############################################### 额外：统计各程序 max_execs   ##################################################
# 每个 PROGRAM 取它最小的 max_execs
max_execs_dict = {}
for PROGRAM in PROGRAMS:
    # 每个 PROGRAM，需要取 REPEAT x #FUZZERS 个 max_execs，然后取最小的
    the_max_execs = -1
    the_max_time  = -1
    max_execs_list = []
    for FUZZER in FUZZERS:
        # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，获取 dfs
        dfs = []
        for result in results:
            fuzz_result = result.get()
            if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                continue
            dfs.append(fuzz_result[4])
        assert(len(dfs) == REPEAT)
        # 从 dfs 中获取 max_execs
        for df in dfs:
            if df["total_execs"].max() > the_max_execs:
                the_max_execs = df["total_execs"].max() 
                the_max_time = df["# relative_time"].max()
            # 只有时间长度达到目标的统计数据才会被加入 max_execs_list，这样可以有效防止死循环的 fuzzing 影响全局
            if (math.ceil(df["# relative_time"].max() / 60) >= SPLIT_NUM-1):
                max_execs_list.append(df["total_execs"].max())
            # max_execs_list.append(df["total_execs"].max())
    # 此时，max_execs_list 的长度 <= REPEAT x len(FUZZERS)
    assert(len(max_execs_list) <= len(FUZZERS) * REPEAT)
    # assert(len(max_execs_list) == len(FUZZERS) * REPEAT)
    # 这个就是这个程序有效的最大的 execs (最小的 max_execs)
    if (len(max_execs_list) > 0):
        max_execs = min(max_execs_list)
    else:
        max_execs = TOTAL_TIME * 60 * int(the_max_execs/the_max_time)
    max_execs_dict[PROGRAM] = max_execs

############################################### 5.绘制 bug-execs 图   ##################################################
for PROGRAM in PROGRAMS:

    plt.figure()  # 创建一个新的图形
    # 获取这个程序的 max_execs，计算 execs_unit
    max_execs = max_execs_dict[PROGRAM]
    execs_unit = (max_execs / int(TOTAL_TIME / SPLIT_UNIT))

    for FUZZER in FUZZERS:
        theSlot = bug_time_dict[PROGRAM + FUZZER]
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
            # 遍历排序后的数据，把 bug 这个属性放进去
            df['bug'] = None
            for idx, row in df.iterrows():
                time = int(row["# relative_time"])
                k = math.ceil(time / 60)
                if k < SPLIT_NUM:
                    df.loc[idx, "bug"] = theSlot[k]

            for _, row in df.iterrows():
                execs = int(row["total_execs"])
                k = math.ceil(execs / execs_unit)
                if k < SPLIT_NUM and row["bug"]:
                    slot[k] = int(row["bug"])
            # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
            # 检查一下，看看是否有中间为 0 的情况，若有，补上
            assert(slot[0] == 0)
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
    plt.title(PROGRAM + " bug-execs graph")
    plt.xlabel('# execs')
    plt.ylabel('# bug')
    # 保存图形为文件: 每个 PROGRAM 画一张图
    plt.savefig('bug_execs_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
    print("finish drawing bug_execs_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
    sys.stdout.flush()

    plt.close()  # 关闭图形

print("============================= finish drawing bug_execs graph part =============================")
sys.stdout.flush()

# 要结束了
pool.close()
pool.join()







