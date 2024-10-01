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
TOTAL_TIME = 24 * 60 # 单位分钟
SPLIT_UNIT = 1  # 每隔 1 分钟
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量
# # 比较所有 fuzzers 的情况
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_empty_path_k_2", "path_fuzzer_empty_path_k_4", "path_fuzzer_empty_path_k_8", \
#     "path_fuzzer_full_path_k_1", "path_fuzzer_full_path_k_2", "path_fuzzer_full_path_k_4", "path_fuzzer_full_path_k_8"]
# 只比较 k=1 和 AFL++ 的情况
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_full_path_k_1"]
# TARGETS = ["php", "libsndfile", "libpng", "libtiff", "libxml2", "sqlite3", "lua"]
FUZZERS = ["aflplusplus", "path_fuzzer_empty_path", "path_fuzzer_full_path", "cov_trans_fuzzer_empty_path", "cov_trans_fuzzer_full_path"]
TARGETS = ["base64", "md5sum", "uniq", "who"]
# 表明这个脚本所运行的文件夹
# WORKDIR = "cache"
WORKDIR = "workdir_1d_REPEAT4_LAVAM"
# 重复次数
REPEAT=4
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = ""
# 决定绘制哪些图，不绘制哪些图
draw_configure = {
    "crash_time"     : False,
    "crash_execs"    : True,
    "seed_time"      : True,
    "seed_execs"     : True,
    "edge_time"      : True,
    "edge_execs"     : True,
    "Throughput_time": True,
}

############################################### 1. 一些函数的定义    ##################################################
# 定义获取子目录的函数
def getsubdir(basedir):
    subdirs = [d for d in os.listdir(basedir) 
        if os.path.isdir(os.path.join(basedir, d)) and not d.startswith('.') ]
    return sorted(subdirs)

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

############################################### 3. 读取所有 plot_data ##################################################
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
    # CHANGE: 如果横轴是 execs，那么需要获取 REPEAT x #FUZZERS 个 max_execs，然后取最小的
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
            max_execs_list.append(df["total_execs"].max())
            if not (math.ceil(df["# relative_time"].max() / 60) >= SPLIT_NUM-1):
                print("PROGRAM = " + PROGRAM)
                print("FUZZER = " + FUZZER)
                print(df["total_execs"].max())
                print(df["# relative_time"].max())
                assert(0)
    # 此时，max_execs_list 的长度达到了 REPEAT x len(FUZZERS)
    assert(len(max_execs_list) == len(FUZZERS) * REPEAT)
    # 这个就是这个程序最大的 execs
    max_execs = min(max_execs_list)


############################################### 4. 绘制 crash_time   ##################################################
if draw_configure["crash_time"]:
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
                        slot[k] = int(row["saved_crashes"])
                # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
                # 检查一下，看看是否有中间为 0 的情况，若有，补上
                assert(slot[0] == 0)
                for i in range(SPLIT_NUM):
                    if i > 1 and slot[i] == 0:
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
        plt.title(PROGRAM + ' crash-time graph')
        plt.xlabel('time(h)')
        plt.ylabel('# crashes')
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig('crash_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        print("finish drawing crash_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()

    print("============================= finish drawing crash_time graph part =============================")
    sys.stdout.flush()

############################################### 5. 绘制 crash_execs  ##################################################
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
        # 处理 dfs 的数据，提取出 crash-execs 数组，总共 REPEAT 个
        slot_list = []
        for df in dfs:
            slot = [0] * SPLIT_NUM
            # 按照相应单位，把 df 中的数据转移到数组上
            # 先给 df 排序
            df = df.sort_values("total_execs")
            print(df)
            exit(0)
            # 遍历排序后的数据
            for _, row in df.iterrows():
                time_s = int(row["# relative_time"])
                k = math.ceil(time_s / 60)
                if k < SPLIT_NUM:
                    slot[k] = int(row["saved_crashes"])
            # CHANGE: 绘制其它图片，对于 slot[i] == 0 的处理方式可能不一样
            # 检查一下，看看是否有中间为 0 的情况，若有，补上
            assert(slot[0] == 0)
            for i in range(SPLIT_NUM):
                if i > 1 and slot[i] == 0:
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
    plt.title(PROGRAM + ' crash-time graph')
    plt.xlabel('time(h)')
    plt.ylabel('# crashes')
    # 保存图形为文件: 每个 PROGRAM 画一张图
    plt.savefig('crash_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
    print("finish drawing crash_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
    sys.stdout.flush()

print("============================= finish drawing crash_time graph part =============================")
sys.stdout.flush()

############################################### 6. 绘制 seed_time    ##################################################

############################################### 7. 绘制 seed_execs   ##################################################

############################################### 8. 绘制 edge_time    ##################################################

############################################### 9. 绘制 edge_execs   ##################################################

############################################### 10. 绘制 Throughput  ##################################################


############################################### 要结束了             ##################################################
pool.close()
pool.join()
exit(0)  


# 在 timeout 限制下来运行一个命令
def sub_run(cmd, timeout):
    try: 
         r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
         return r
    except subprocess.TimeoutExpired:
        print("time out")
        return None
    return None

# LAVAM commands
# afl-fuzz -i corpus/base64 -o findings -m none -c cmplog/base64 -d -- afl/base64 -d @@
# afl-fuzz -i corpus/md5sum -o findings -m none -c cmplog/md5sum -d -- afl/md5sum -c @@
# afl-fuzz -i corpus/uniq -o findings -m none -c cmplog/uniq -d -- afl/uniq @@
# afl-fuzz -i corpus/who -o findings -m none -c cmplog/who -d -- afl/who @@
# MAGMA commands
# afl-fuzz -i corpus/exif -o findings -m none -c cmplog/exif -d -- afl/exif -
# afl-fuzz -i corpus/libpng_read_fuzzer -o findings -m none -c cmplog/libpng_read_fuzzer -d -- afl/libpng_read_fuzzer -

# CHANGE: 也许需要补充 program_args
# 这里的 program_args 可以是为了找 edges，也可以是为了找 bugs
edge_program_args = {
        # lAVAM
        "base64": "-d",        
        "md5sum": "-c",        
        "uniq": "",        
        "who": "",        
        # # MAGMA
        # "libpng_read_fuzzer": "",        
        # "sndfile_fuzzer": "",
        # "tiff_read_rgba_fuzzer": "",
        # "tiffcp": "-M",
        # "libxml2_xml_read_memory_fuzzer": "",
        # "xmllint": "--valid --oldxml10 --push --memory"
}

bug_program_args = {
        # lAVAM
        "base64": "-d",        
        "md5sum": "-c",        
        "uniq": "",        
        "who": "",        
        # # MAGMA
        # "libpng_read_fuzzer": "",        
        # "sndfile_fuzzer": "",
        # "tiff_read_rgba_fuzzer": "",
        # "tiffcp": "-M",
        # "libxml2_xml_read_memory_fuzzer": "",
        # "xmllint": "--valid --oldxml10 --push --memory"
}

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'mapfile', '-m', 'none', '-e', '--', 'PUT']

# 转化时间为正确单位的函数
def convert_Time(original_time):
    # CHANGE: 正确地转化时间
    # 先转为秒
    original_time /= 1000
    # 再转为分
    original_time /= 60
    # 再转为小时
    original_time /= 60
    # 向下取整
    original_time = int(original_time)
    return original_time

# 这个函数的目的：使用 afl-showmap 获取输入文件 filename 对程序 put 触发的 edges 合集，存放于字典中
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
# 参数 mapfile: edgemap 的文件实际路径
def getEdges(put, program, filename, mapfile):
    triggered_edges_set = {}
    command = copy.deepcopy(base_command)
    command[-1] = put
    assert(edge_program_args[program] is not None)
    if edge_program_args[program]:
        command.append(edge_program_args[program])
    command.append(filename)
    command[5] = mapfile

    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    # 打印命令的标准输出
    # print("标准输出:")
    # print(result.stdout)

    with open(mapfile, 'r') as the_mapfile:
        for line in the_mapfile:
            # 去除每行的前后空白字符
            line = line.strip()
            # 分割每行的字符串和整数
            if ':' in line:
                key, value = line.split(':', 1)
                # 存入字典
                triggered_edges_set[key] = int(value)

    return triggered_edges_set 

"""这个脚本应该在 cache 文件夹下运行"""



# 定义获取文件的函数
def getfiles(basedir):
    files = [f for f in os.listdir(basedir) 
        if os.path.isfile(os.path.join(basedir, f)) and not f.startswith('.')]
    return files

"""用来收集 edge_time 数据的工作函数"""
def edge_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    edge_time_slot = [0] * SPLIT_NUM
    edge_time_slot_dict = [{} for _ in range(SPLIT_NUM)] 
    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    queuedir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    # 无论何时，PUT 都是同一个
    put = "aflplusplus" + "/" + TARGET + "/" + thePROGRAM + "/0/afl/" + thePROGRAM

    # 先获取 crashes 的 edges
    files = getfiles(crashdir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(crash_files) = " + str(len(files)))
    sys.stdout.flush()

    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:

            # 如果是 +pat 种子，那么跳过，因为它必不增加 edge-cov 
            pat_matches = re.findall(r"\+pat", crash_file)
            assert(len(pat_matches) < 2)
            if pat_matches:
                continue

            crash_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if crash_time < SPLIT_NUM:
                # NOTE: 计算这个单独文件触发的边缘字典
                triggered_edges_set = getEdges(put, thePROGRAM, crashdir + crash_file, "mapfile" + str(task_count))
                # 在边缘字典槽里更新
                edge_time_slot_dict[crash_time].update(triggered_edges_set)

    # 再获取 seeds 的 edges
    files = getfiles(queuedir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(seed_files) = " + str(len(files)))
    sys.stdout.flush()

    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:

            # 如果是 +pat 种子，那么跳过，因为它必不增加 edge-cov 
            pat_matches = re.findall(r"\+pat", seed_file)
            assert(len(pat_matches) < 2)
            if pat_matches:
                continue

            seed_time = convert_Time(int(matches[0]))

            if seed_time < SPLIT_NUM:
                # NOTE: 计算这个单独文件触发的边缘字典
                triggered_edges_set = getEdges(put, thePROGRAM, queuedir + seed_file, "mapfile" + str(task_count))
                # 在边缘字典槽里更新
                edge_time_slot_dict[seed_time].update(triggered_edges_set)
                
    # 先从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        edge_time_slot_dict[i+1].update(edge_time_slot_dict[i])

    # 再从字典数组转为 edges 数量数组
    for i in range(SPLIT_NUM):
        edge_time_slot[i] = len(edge_time_slot_dict[i])

    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, edge_time_slot)

"""用来收集 non_bug_crash_time 数据的工作函数"""
def non_bug_crash_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    non_bug_crash_time_slot = [0] * SPLIT_NUM

    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    # 无论何时，PUT 都是同一个
    put = "aflplusplus" + "/" + TARGET + "/" + thePROGRAM + "/0/afl/" + thePROGRAM

    # 先获取 crashes 里的 bugs
    files = getfiles(crashdir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(crash_files) = " + str(len(files)))
    sys.stdout.flush()

    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            # NOTE: 时间转换
            crash_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if crash_time < SPLIT_NUM:
                # 看看这个文件是否触发 validated_bugs
                cmd = [put]            
                assert(bug_program_args[thePROGRAM] is not None)
                if bug_program_args[thePROGRAM]:
                    cmd.append(bug_program_args[thePROGRAM])
                cmd.append(crashdir + crash_file)
                # 6 秒限制超时，运行该命令
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                # 用来表示这个 crash_file 是否触发已知 bug 的 FLAG
                iscrash = False
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bug_time_dict 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        print("%s in: %s" % (line, crash_file))
                        iscrash = True

                if False == iscrash:
                    non_bug_crash_time_slot[crash_time] += 1
                
    # 先从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        non_bug_crash_time_slot[i+1] += non_bug_crash_time_slot[i]

    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, non_bug_crash_time_slot)


"""用来收集 magma bug_time 数据的工作函数"""
def magma_bug_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    pass

"""用来收集 lavam bug_time 数据的工作函数"""
def lavam_bug_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    bug_time_slot = [0] * SPLIT_NUM
    bug_time_dict = {}
    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    queuedir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    # 无论何时，PUT 都是同一个
    put = "aflplusplus" + "/" + TARGET + "/" + thePROGRAM + "/0/afl/" + thePROGRAM

    # 先获取 crashes 里的 bugs
    files = getfiles(crashdir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(crash_files) = " + str(len(files)))
    sys.stdout.flush()

    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            # NOTE: 时间转换
            crash_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if crash_time < SPLIT_NUM:
                # 看看这个文件是否触发 validated_bugs
                cmd = [put]            
                assert(bug_program_args[thePROGRAM] is not None)
                if bug_program_args[thePROGRAM]:
                    cmd.append(bug_program_args[thePROGRAM])
                cmd.append(crashdir + crash_file)
                # 6 秒限制超时，运行该命令
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bug_time_dict 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        if cur_id not in bug_time_dict:                        
                            print("  Trigger %5d in: %s" % (cur_id, crash_file))
                            bug_time_dict[cur_id] = crash_time
                            bug_time_slot[crash_time] += 1

    # 再获取 seeds 里的 bugs
    files = getfiles(queuedir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(seed_files) = " + str(len(files)))
    sys.stdout.flush()

    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:

            # 如果是 +pat 种子，那么跳过，因为它大概率不触发新 bugs，否则不会被列入 pat+ 池子里
            pat_matches = re.findall(r"\+pat", seed_file)
            assert(len(pat_matches) < 2)
            if pat_matches:
                continue

            # NOTE: 时间转换
            seed_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if seed_time < SPLIT_NUM:
                # 看看这个文件是否触发 validated_bugs
                cmd = [put]            
                assert(bug_program_args[thePROGRAM] is not None)
                if bug_program_args[thePROGRAM]:
                    cmd.append(bug_program_args[thePROGRAM])
                cmd.append(queuedir + seed_file)
                # 6 秒限制超时，运行该命令
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bug_time_dict 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        if cur_id not in bug_time_dict:                        
                            print("  Trigger %5d in: %s" % (cur_id, seed_file))
                            bug_time_dict[cur_id] = seed_time
                            bug_time_slot[seed_time] += 1
                        # 如果之前的找到的 bug 时间更晚，那么做个更新
                        if bug_time_dict[cur_id] > seed_time:                        
                            print("  early Trigger %5d in: %s" % (cur_id, seed_file))
                            bug_time_slot[bug_time_dict[cur_id]] -= 1
                            bug_time_dict[cur_id] = seed_time
                            bug_time_slot[seed_time] += 1
                
    # 先从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        bug_time_slot[i+1] += bug_time_slot[i]

    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, bug_time_slot)

"""用来收集 seed_time 数据的工作函数"""
def seed_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    seed_time_slot = [0] * SPLIT_NUM
    path = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    files = getfiles(path)
    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:

            seed_time = convert_Time(int(matches[0]))

            # 如果时间戳没有超过配置最大值，那么记录数据
            if seed_time < SPLIT_NUM:
                seed_time_slot[seed_time] += 1
    # 从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        seed_time_slot[i+1] += seed_time_slot[i]
    # 打印表示目前任务已完成(需要加锁)
    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, seed_time_slot)

"""用来收集 crash_time 数据的工作函数"""
def crash_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    crash_time_slot = [0] * SPLIT_NUM
    path = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    files = getfiles(path)
    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:

            crash_time = convert_Time(int(matches[0]))

            # 如果时间戳没有超过配置最大值，那么记录数据
            if crash_time < SPLIT_NUM:
                crash_time_slot[crash_time] += 1
    # 从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        crash_time_slot[i+1] += crash_time_slot[i]
    # 打印表示目前任务已完成(需要加锁)
    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, crash_time_slot)

# CHANGE: 这里根据不同的数据收集任务需要改变
"""总工作函数"""
def worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    return seed_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count)

def main():




    # 绘图:
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数组，随后求平均
            count = 0
            result_time_slot = [[] for _ in range(REPEAT)]
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                result_time_slot[count] = fuzz_result[4]
                count += 1
            assert(count == REPEAT)
            # 求平均，四舍五入
            result_time_slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    result_time_slot_avg[i] += result_time_slot[k][i]
                result_time_slot_avg[i] /= REPEAT
                result_time_slot_avg[i] = round(result_time_slot_avg[i])
            # 开始绘图  CHANGE:
            x = [ (i+1) for i in range(SPLIT_NUM) ]
            y = result_time_slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 添加标题和标签 CHANGE:
        # 注意：edges 最好使用 min 作为横轴单位！！！
        plt.title(PROGRAM + ' seed-time graph')
        plt.xlabel('time(h)')
        plt.ylabel('# seeds')
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig('seed_time_' + PROGRAM + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'

    print("total " + str(len(results)) + " fuzzing result collect tasks")
    sys.stdout.flush()

    # 要结束了
    pool.close()
    pool.join()
    exit(0)

if __name__ == '__main__':
    main()


