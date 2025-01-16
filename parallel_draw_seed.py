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

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

######################################## 2. 并行读取绘图所需数据 (queue) #################################### doing



# 被并行执行的函数 --------------------------------------------------------------- start 
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME):
    # 返回一个 DataFrame
    InputFile_list = []
    queue_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/queue"
    allfiles = getfiles(queue_path)
    pattern = r"time:(\d+),execs:(\d+),"
    for file in allfiles:
        # unique 文件夹内的都被筛过，必定 match
        match = re.search(pattern, file)
        assert(match)
        time_val = int(match.group(1))  # 提取 time
        execs_val = int(match.group(2))  # 提取 execs
        # 先转为秒
        time_val /= 1000
        # 再把时间转为分钟，这里使用向上取整，因为我们希望能保留 time = 0 和 execs = 0，其它都算作1分钟的
        time_val = math.ceil(time_val / 60)
        # 构建为 InputFile 对象
        inputfile = InputFile(time=time_val, execs=execs_val)
        InputFile_list.append(inputfile)
    # 按照时间排序
    InputFile_list.sort(key=lambda x : x.time)
    # 构建 DataFrame
    time_list = []
    execs_list = []
    corpus_count_list = []
    corpus_count = 0
    for inputfile in InputFile_list:
        time_list.append(inputfile.time)
        execs_list.append(inputfile.execs)
        corpus_count += 1
        corpus_count_list.append(corpus_count)
    data = {
        "# relative_time" : time_list,
        "total_execs"     : execs_list,
        "corpus_count"     : corpus_count_list,
    }
    df = pd.DataFrame(data)
    # 按 '# relative_time' 分组，找到每组的最大 'total_execs'
    df['total_execs'] = df.groupby('# relative_time')['total_execs'].transform('max')
    # 按 '# relative_time' 分组，找到每组的最大 'corpus_count'
    df['corpus_count'] = df.groupby('# relative_time')['corpus_count'].transform('max')
    # 按 '# relative_time' 列去重，保留第一行（默认）
    df = df.drop_duplicates(subset='# relative_time', keep='first')

    # 打印信息，表示这个数据收集任务已完成
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME, df)
# 被并行执行的函数 --------------------------------------------------------------- end

results = parallel_framework(collect_data_worker, need_parallel_id=False)

############################################### 3. 统计各程序 max_execs   ################################################## 完成
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

############################################### 4. 定义绘图函数   ################################################## 完成
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
                dfs.append(fuzz_result[4])
            # 验证 REPEAT 是否和 dfs 收集到的数量一致
            assert(len(dfs) == REPEAT)
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
                    # 取得这一行的时间(单位：分)
                    k = int(row["# relative_time"])
                    # 部分实验可能会运行超过规定的时间，我们把超过规定时间的数据忽略掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # 如果这个属性是 “积累属性”，那么就需要填补 slot 中为 0 的部分
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            # 验证，slot_list 的长度必须等于 REPEAT
            assert(len(slot_list) == REPEAT)
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
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

# name: 决定 y轴 和图的名字
# colname: plot_data 中和 y轴 相应那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？ (crash, seed 属于积累属性, Throughput 不属于)
# 或者说，种子数量、crash数量、bug 数量这些是可以积累的，但是 “速度” 是不可以积累的
# 路程是可以积累的，速度是不能积累的。学习的知识是可以积累的，学习的速度是不能积累的
# 这就是 “积累” 属性
def draw_execs(name: str, colname: str, accumulate: bool):
    # 每一个 PROGRAM 绘制一张图 (FUZZERS 是这张图上的 legend)
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形
        # 获取这个程序的 max_execs，并计算 execs_unit
        # 后续每一下标表示 “经历了一个 execs_unit” 这么多的执行次数
        max_execs = max_execs_dict[PROGRAM]
        execs_unit = (max_execs / int(TOTAL_TIME / SPLIT_UNIT))

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，储存在 dfs 列表中
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[4])
            # 验证 REPEAT 是否和 dfs 收集到的数量一致
            assert(len(dfs) == REPEAT)
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME-parallel_id 的 plot_data，可以绘制成一条线
            # 我们要对这些 df 的值取平均
            # slot_list 就是用来存放绘图数据数组的列表
            slot_list = []
            for df in dfs:
                # 用来绘图的数据数组
                slot = [0] * SPLIT_NUM
                # 因为是 draw_execs 先给 df 按照执行次数排序
                df = df.sort_values("total_execs")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    # 取得这一行的执行次数
                    execs = int(row["total_execs"])
                    # 根据 execs_unit 计算下标，向上取整
                    k = math.ceil(execs / execs_unit)
                    # 部分 plot_data 可能含有远超于 SPLIT_NUM 的数据，它们不会被
                    # 绘制进图片了，抛弃掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # 如果这个属性是 “积累属性”，那么就需要填补 slot 中为 0 的部分
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            # 验证，slot_list 的长度必须等于 REPEAT 
            assert(len(slot_list) == REPEAT)
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
                slot_avg[i] = math.ceil(slot_avg[i])
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)

            # 有了 slot_avg 就能绘图了
            # 开始绘图
            # x 轴表示执行次数
            x = [ i*execs_unit for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 这个 PROPGRAM 绘制完毕后，要命名
        # 设置标题
        plt.title(PROGRAM + " " + name + '-execs graph')
        # 设置 x 轴
        plt.xlabel('# execs')
        # 设置 y 轴
        plt.ylabel('# ' + name)
        # 设置文件名和文件类型 (png, svg, pdf ....)
        plt.savefig(name + '_execs_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        # 打印日志标识成功绘制这个图片
        print("finish drawing " + name + "_execs_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()
        # 关闭图形，节约内存
        plt.close() 

    # 打印日志：成功绘制完某一类型的图片
    print("============================= finish drawing " + name + "_execs graph part =============================")
    sys.stdout.flush()

############################################### 5. 绘制 throughput_time 图    ################################################## 完成

if draw_configure["seed_time"]:
    draw_time("seed", "corpus_count", True)

if draw_configure["seed_execs"]:
    draw_execs("seed", "corpus_count", True)

############################################### 6. 要结束了                   ################################################## 完成
# 关闭并行任务池子、退出
pool.close()
pool.join()
exit(0)  

