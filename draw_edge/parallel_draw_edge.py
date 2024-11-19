import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess
import math
import csv
import pandas as pd
from datetime import datetime
import numpy as np

# execs_unit_dict = None
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
    "edge_time"     : True,
    "edge_execs"    : True,
}

############################################### 一些常用常数、函数的定义(尽量别修改) ##############################
SPLIT_UNIT = 1
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量

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

############################################### 1. 验证 fuzzing result 是否有异常 ##################################################
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

############################################### 2. 定义并行读取绘图所需数据 (edges) 的函数 ##################################################
# LAVAM commands
# afl-fuzz -i corpus/base64 -o findings -m none -c cmplog/base64 -d -- afl/base64 -d @@
# afl-fuzz -i corpus/md5sum -o findings -m none -c cmplog/md5sum -d -- afl/md5sum -c @@
# afl-fuzz -i corpus/uniq -o findings -m none -c cmplog/uniq -d -- afl/uniq @@
# afl-fuzz -i corpus/who -o findings -m none -c cmplog/who -d -- afl/who @@
# MAGMA commands
# afl-fuzz -i corpus/lua -o findings -m none -c cmplog/lua -d -- afl/lua
# afl-fuzz -i corpus/exif -o findings -m none -c cmplog/exif -d -- afl/exif - 
# afl-fuzz -i corpus/sndfile_fuzzer -o findings -m none -c cmplog/sndfile_fuzzer -d -- afl/sndfile_fuzzer @@
# afl-fuzz -i corpus/libpng_read_fuzzer -o findings -m none -c cmplog/libpng_read_fuzzer -d -- afl/libpng_read_fuzzer - 
# afl-fuzz -i corpus/tiff_read_rgba_fuzzer -o findings -m none -c cmplog/tiff_read_rgba_fuzzer -d -- afl/tiff_read_rgba_fuzzer - 
# afl-fuzz -i corpus/tiffcp -o findings -m none -c cmplog/tiffcp -d -- afl/tiffcp -M @@ tmp.out
# afl-fuzz -i corpus/libxml2_xml_read_memory_fuzzer -o findings -m none -c cmplog/libxml2_xml_read_memory_fuzzer -d -- afl/libxml2_xml_read_memory_fuzzer - 
# afl-fuzz -i corpus/xmllint -o findings -m none -c cmplog/xmllint -d -- afl/xmllint --valid --oldxml10 --push --memory @@
# afl-fuzz -i corpus/sqlite3_fuzz -o findings -m none -c cmplog/sqlite3_fuzz -d -- afl/sqlite3_fuzz - 
# afl-fuzz -i corpus/server -o findings -m none -c cmplog/server -d -- afl/server - 
# afl-fuzz -i corpus/client -o findings -m none -c cmplog/client -d -- afl/client - 
# afl-fuzz -i corpus/x509 -o findings -m none -c cmplog/x509 -d -- afl/x509 - 

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
# singularity run ./afl-showmap.sif /magma/fuzzers/aflplusplus/repo/afl-showmap -o mapfile -m none -e -- ....
# 这个命令可以生成一个名为 "mapfile" 的文件，该文件包含某个特定种子能够触发的 edges 的编号
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'MAPFILE', '-m', 'none', '-e', '--', 'PUT']

# 这些 program_args 表示需要各个 PUT 在单独运行某些种子时，需要添加的参数
edge_program_args = {
        # lAVAM
        "base64": ["-d", "INPUT_FILE"],        
        "md5sum": ["-c", "INPUT_FILE"],        
        "uniq": ["INPUT_FILE"],        
        "who": ["INPUT_FILE"],        
        # MAGMA
        "lua": ["INPUT_FILE"],
        "exif": ["INPUT_FILE"],
        "sndfile_fuzzer": ["INPUT_FILE"],
        "libpng_read_fuzzer": ["INPUT_FILE"],        
        "tiff_read_rgba_fuzzer": ["INPUT_FILE"],
        "tiffcp": ["-M", "INPUT_FILE", "TMPOUT"],
        "libxml2_xml_read_memory_fuzzer": ["INPUT_FILE"],
        "xmllint": ["--valid", "--oldxml10", "--push", "--memory", "INPUT_FILE"],
        "sqlite3_fuzz": ["INPUT_FILE"],
        "client": ["INPUT_FILE"],
        "server": ["INPUT_FILE"],
        "x509": ["INPUT_FILE"],
}

# 获取某个文件能触发的 edges 编号
# 这个函数的目的：使用 afl-showmap 获取输入文件 filename 对程序 put 触发的 edges 合集，通过一个字典返回
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PUT 对应的 PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
# 参数 mapfile: 用来存放 edgemap 的文件路径
# task_count: 表示这是第几个并行任务
def getEdges(put, program, filename, mapfile, task_count):
    # triggered_edges_set 包含 filename 能触发的 edges 的编号
    triggered_edges_set = {}
    # 深拷贝
    command = copy.deepcopy(base_command)
    # 把 PUT占位符 替换成实际的 put 文件路径
    command[-1] = put
    # 把 MAPFILE 占位符 替换成实际的 mapfile 文件路径
    command[5] = mapfile
    # 断言：对应 PROGRAM 的参数在字典中一定存在
    assert(edge_program_args[program] is not None)
    # 往命令行列表添加 PROGRAM 参数
    for arg in edge_program_args[program]:
        if arg == "INPUT_FILE":
            command.append(filename)
        elif arg == "TMPOUT":
            command.append("tmp.out." + str(task_count))
        else:
            command.append(arg)

    # 如果当前正在处理的 PROGRAM 是 tiffcp，那么需要做一些特殊处理。
    # 原因是 tiffcp 不能识别 AFL++ 的 crash 文件命名方式，所以需要对 AFL++ 的 crash 文件重命名
    if program == "tiffcp":
        tmpcmd = ["cp", filename, "deadbeef_bug." + str(task_count)]
        try:
            result = subprocess.run(tmpcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
        except:
            print("Unexpected error at tiffcp: " + filename)
            print("result.stdout =============================")
            print(result.stdout)
            print("result.stderr =============================")
            print(result.stderr)
            assert(0)
        # 重命名成功后，把 command 中的输入文件替换成重命名后的文件
        command[12] = tmpcmd[2]

    # 执行 command，产生 mapfile
    try: 
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
    except:
        print("result.stdout =============================")
        print(result.stdout)
        print("result.stderr =============================")
        print(result.stderr)
        print("===== or TIME OUT, filename = " + filename)
        assert(0)

    # # 打印命令的标准输出，这个一般在 DEBUG 时用
    # print("标准输出:")
    # print(result.stdout)

    # 打开产生的 mapfile 文件，把触发的 edges 存入 triggered_edges_set
    with open(mapfile, 'r') as the_mapfile:
        for line in the_mapfile:
            # 去除每行的前后白字符
            line = line.strip()
            # 分割每行的字符串和整数
            if ':' in line:
                key, value = line.split(':', 1)
                # 存入字典
                triggered_edges_set[key] = 1

    # 返回字典
    return triggered_edges_set 

# 一个全局变量，被所有并行任务共享，标识已经完成的任务数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

class InputFile:
    def __init__(self, time: int, execs: int, filename: str):
        self.time = time
        self.execs = execs
        self.filename = filename
        self.edges = 0

# 被并行执行的函数 --------------------------------------------------------------- start
def edge_data_collector(FUZZER, TARGET, PROGRAM, TIME, task_count):
    df = None
    try:
        # 第一步：把 crash 和 queue 下所有文件读取出来，去掉包含 "+pat" 的文件，随后按照 "time" 排序
        # 加个 assert()，表示一个列表里绝对没有两个文件的 time 是相等的
        # 第二步：按照排序的顺序，逐个使用 getEdges 获取触发的 edges，记录数量，维护一个 class
        # class 包含：time, execs, triggered_edges
        # 第三步，根据第二部得到的 class 列表，构造一个 dataFrame，随后返回这个 dataframe

        # 无论何时，用来计算触发 edges 的 PUT 都是同一个
        put = "aflplusplus" + "/" + TARGET + "/" + PROGRAM + "/0/afl/" + PROGRAM

        # 第一步：把 crash 和 queue 下所有文件读取出来，去掉包含 "+pat" 的文件，随后按照 "time" 排序
        # 加个 assert()，表示一个列表里绝对没有两个文件的 time 是相等的
        # 读取 crash 和 queue 文件夹下所有文件
        crashdir = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/default/crashes/"
        queuedir = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/default/queue/"
        crashfiles = getfiles(crashdir)
        queuefiles = getfiles(queuedir)
        # 去掉包含 "+pat" 文件，以及非常规文件，比如 README.txt
        filterfiles = []
        # 先从 crashfiles 中过滤
        for file in crashfiles:
            pat_match = re.findall(r"\+pat", file)
            assert(len(pat_match) < 2)
            if pat_match:
                continue
            match_time  = re.findall(r"time:(\d+)", file)
            match_execs = re.findall(r"execs:(\d+)", file)
            # 过滤掉非常规文件，比如 README.txt
            if (not match_time) or (not match_execs):
                continue
            assert(len(match_time) < 2)
            assert(len(match_execs) < 2)
            time_ms = int(match_time[0])
            execs = int(match_execs[0])
            inputfile = InputFile(time=time_ms, execs=execs, filename=(crashdir + file))
            filterfiles.append(inputfile)
        # 再从 queuefiles 中过滤
        for file in queuefiles:
            pat_match = re.findall(r"\+pat", file)
            assert(len(pat_match) < 2)
            if pat_match:
                continue
            match_time  = re.findall(r"time:(\d+)", file)
            match_execs = re.findall(r"execs:(\d+)", file)
            # 过滤掉非常规文件，比如 README.txt
            if (not match_time) or (not match_execs):
                continue
            assert(len(match_time) < 2)
            assert(len(match_execs) < 2)
            time_ms = int(match_time[0])
            execs = int(match_execs[0])
            inputfile = InputFile(time=time_ms, execs=execs, filename=(queuedir + file))
            filterfiles.append(inputfile)
        # 按照 time 排序
        filterfiles.sort(key=lambda x : x.time)
        # 断言：遍历 filterfiles，看看是否有任意两个元素的 time 相等
        # 一开始有大量种子是 time 0 的，因为它们本就存在于 corpus 中，这部分要 skip
        for i in range(len(filterfiles) - 1):
            assert(filterfiles[i].time == 0 or filterfiles[i].time < filterfiles[i+1].time)

        # 第二步：按照排序的顺序，逐个使用 getEdges 获取触发的 edges，记录数量，维护一个 class
        # class 包含：time, execs, triggered_edges
        edge_set_accumulate = {}
        for inputfile in filterfiles:
            edge_set = getEdges(put, PROGRAM, inputfile.filename, "mapfile" + str(task_count), task_count)
            edge_set_accumulate.update(edge_set)
            inputfile.edges = len(edge_set_accumulate)

        # 第三步，根据第二部得到的 class 列表，构造一个 dataFrame，随后返回这个 dataframe
        time_list  = []
        execs_list = []
        edges_list = []
        for inputfile in filterfiles:
            time_list.append(inputfile.time)
            execs_list.append(inputfile.execs)
            edges_list.append(inputfile.edges)
        data = {
            "# relative_time" : time_list,
            "total_execs"     : execs_list,
            "edges_found"     : edges_list,
        }
        df = pd.DataFrame(data)
        # relative_time 这一列是 ms 为单位，把它转为 s 为单位
        df['# relative_time'] = int(df['# relative_time'] / 1000)

        print(df)
        sys.stdout.flush()

        with finished_tasks.get_lock():
            finished_tasks.value += 1
            print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
            sys.stdout.flush()
    except Exception as e:
        print(f"Exception caught in main process: {e}")
    assert(df is not None)
    return (FUZZER, TARGET, PROGRAM, TIME, df)
# 被并行执行的函数 --------------------------------------------------------------- end

# ############################################### 3. 并行收集所有 edge 数据，包括 edge_time 和 edge_execs    ################################################## 审查完毕

# 获取 CPU cores 总数
num_cores = multiprocessing.cpu_count()
print(f'CPU 核心数量: {num_cores}')
sys.stdout.flush()

# 创建一个进程池，池中进程的数量等于 CPU 核心数量
pool = multiprocessing.Pool(num_cores)

# 储存结果的队列
results = []

# 任务数计数器，也可以叫任务序号计数器
task_count = 0

# 为每一个 program-fuzzer-repeat_time 收集 edges 数据
for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
        # 收集这个 PROGRAM-FUZZER 的所有 REPEAT_times 的 edges 数据

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

                # 分配一个 CPU cores，让它收集当前 PROGRAM-FUZZER-TIME 的 edges 信息，结果存放于 results 列表
                for TIME in TIMES:
                    result = pool.apply_async(edge_data_collector, (FUZZER, TARGET, PROGRAM, TIME, task_count))
                    task_count += 1
                    results.append(result)

# 打印看看一共有多少个并行任务在运行
print(f"================== There are {len(results)} data collect tasks in total ==================")
sys.stdout.flush()

# 等待所有并行任务结束
for result in results:
    result.wait()

############################################### 4. 统计各程序 max_execs   ##################################################
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

############################################### 5. 定义绘图函数   ##################################################
# name: 决定 y轴 和图的名字
# colname: df中和 y轴 相应那一列的列名
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
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME 的 edges，可以绘制成一条线
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
                # edge 的话，corpus 中的种子也被算入了，corpus 的种子 time_s = 0，所以 slot[0] != 0
                # assert(slot[0] == 0)
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
# colname: df中和 y轴 相应那一列的列名
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
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME 的 edges，可以绘制成一条线
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
                    # 部分 edges 可能含有远超于 SPLIT_NUM 的数据，它们不会被
                    # 绘制进图片了，抛弃掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # edge 的话，corpus 中的种子也被算入了，corpus 的种子 execs = 0，所以 slot[0] != 0
                # assert(slot[0] == 0)
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

############################################### 6. 绘制 edge_time   ##################################################
if draw_configure["edge_time"]:
    draw_time("edge", "edges_found", True)

############################################### 7. 绘制 edge_execs  ##################################################
if draw_configure["edge_execs"]:
    draw_execs("edge", "edges_found", True)

############################################### 10. 要结束了             ##################################################
# 关闭并行任务池子、退出
pool.close()
pool.join()
exit(0)  


