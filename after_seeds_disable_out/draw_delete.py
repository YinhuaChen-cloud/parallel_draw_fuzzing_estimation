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
TOTAL_TIME = 60 * 60 # 单位分钟
SPLIT_UNIT = 1  # 每隔 1 分钟
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量
FUZZERS = ["periodic_fuzzer_empty_path_k_1", "periodic_fuzzer_full_path_k_1"]
TARGETS = ["php", "libsndfile", "libpng", "libtiff", "libxml2", "sqlite3", "lua"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# 重复次数
REPEAT=1
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_delete"
# # 决定绘制哪些图，不绘制哪些图
# draw_configure = {
#     "crash_time"     : True,
#     "crash_execs"    : False,
#     "seed_time"      : True,
#     "seed_execs"     : False,
#     "edge_time"      : False,
#     "edge_execs"     : False,
#     "throughput_time": False,
# }

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
    return files

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

############################################### 3. 绘制 seed_time ##################################################

TOTAL_TIME = 60 * 60 # 单位分钟

x = [i for i in range(0, TOTAL_TIME, 10)]
x.append(TOTAL_TIME)

for PROGRAM in PROGRAMS:
    plt.figure()  # 创建一个新的图形

    for FUZZER in FUZZERS:
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

                ys = []
                for TIME in TIMES:
                    path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME
                    allsubdirs = getsubdir(path)
                    allsubdirs = [subdir for subdir in allsubdirs if re.match(r'^corpus\.\d+$', subdir)]

                    y = [0] * len(x)

                    for time in x:
                        files = []
                        if os.path.isdir(path + "/" + "corpus." + str(time*60)):
                            files = getfiles(path + "/" + "corpus." + str(time*60))
                        index = int(time/10)
                        y[index] = len(files)
                    
                    for time in x:
                        index = int(time/10)
                        if(y[index] == 0 and index != 0):
                            y[index] = y[index-1]
                        
                    ys.append(y)

                try_times = len(TIMES)
                avg_y = [0] * len(x)
                for i in range(len(x)):
                    for k in range(try_times):
                        avg_y[i] += ys[k][i]
                    avg_y[i] = avg_y[i] / try_times
                
                plot_x = [ (i/60) for i in x ]
                plot_y = avg_y
                # 绘制图形
                plt.plot(plot_x, plot_y, linestyle='-', label=FUZZER) 
                # 添加图例
                plt.legend()

    # CHANGE: 绘制其它图片，这里的标题可能不一样
    # 添加标题和标签
    # 注意：edges 最好使用 min 作为横轴单位！！！
    plt.title(PROGRAM + " seed-time graph")
    plt.xlabel('time(h)')
    plt.ylabel("# seeds")
    # 保存图形为文件: 每个 PROGRAM 画一张图
    plt.savefig('seed_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
    print("finish drawing seed_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
    sys.stdout.flush()

    plt.close()  # 关闭图形

print("============================= finish drawing seed_time graph part =============================")
sys.stdout.flush()

exit(0)





# x = []
# for subdir in allsubdirs:
#     found_numbers = re.findall(r'\d+', subdir)  # 查找所有数字
#     assert(len(found_numbers) == 1)
#     x.extend(found_numbers)  # 将找到的数字添加到新列表中
# # 转换为整数列表
# x = [int(integer) for integer in x]
# x = sorted(x)
# print(x)


#             if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
#                 continue
#             dfs.append(fuzz_result[4])
#         assert(len(dfs) == REPEAT)
#         # CHANGE: 绘制其它图片，提取的数据要变化
#         # 处理 dfs 的数据，提取出 crash-time 数组，总共 REPEAT 个
#         slot_list = []
#         for df in dfs:
#             slot = [0] * SPLIT_NUM
#             # 按照相应单位，把 df 中的数据转移到数组上
#             # 先给 df 排序
#             df = df.sort_values("# relative_time")
#             # 遍历排序后的数据
#             for _, row in df.iterrows():
#                 time_s = int(row["# relative_time"])
#                 k = math.ceil(time_s / 60)
#                 if k < SPLIT_NUM:
#                     slot[k] = int(row[colname])
#             # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
#             # 检查一下，看看是否有中间为 0 的情况，若有，补上
#             assert(slot[0] == 0)
#             if accumulate:
#                 for i in range(SPLIT_NUM):
#                     if i > 0 and slot[i] == 0:
#                         slot[i] = slot[i-1]
#             slot_list.append(slot)
#         assert(len(slot_list) == REPEAT)
#         # CHANGE: 绘制其它图片，对小数点的处理方式可能不一样
#         # 求平均，改成向上取整
#         slot_avg = [0] * SPLIT_NUM
#         for i in range(SPLIT_NUM):
#             for k in range(REPEAT):
#                 slot_avg[i] += slot_list[k][i]
#             slot_avg[i] /= REPEAT
#             slot_avg[i] = math.ceil(slot_avg[i])

#         # CHANGE: 绘制其它图片，这里的 x 轴可能不一样
#         # 开始绘图
#         x = [ (i/60) for i in range(SPLIT_NUM) ]
#         y = slot_avg
#         # 绘制图形
#         plt.plot(x, y, linestyle='-', label=FUZZER) 
#         # 添加图例
#         plt.legend()

#     # CHANGE: 绘制其它图片，这里的标题可能不一样
#     # 添加标题和标签
#     # 注意：edges 最好使用 min 作为横轴单位！！！
#     plt.title(PROGRAM + " " + name + '-time graph')
#     plt.xlabel('time(h)')
#     plt.ylabel('# ' + name)
#     # 保存图形为文件: 每个 PROGRAM 画一张图
#     plt.savefig(name + '_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
#     print("finish drawing " + name + "_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
#     sys.stdout.flush()

#     plt.close()  # 关闭图形

# print("============================= finish drawing " + name + "_time graph part =============================")
# sys.stdout.flush()



