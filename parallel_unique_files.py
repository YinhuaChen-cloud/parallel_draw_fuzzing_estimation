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
import hashlib
import shutil

############################################### 0. 配置部分         ################################################## 完成
FUZZERS = ["aflplusplus", "fixversion"]
TARGETS = ["base64", "libpng", "libsndfile", "libtiff", "libxml2", "md5sum", "php", "sqlite3", "uniq", "who"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# 重复次数
REPEAT=1
# 如果开启了并行 fuzz，那么 Master-Slave 机制下的 IDs 列表
PARALLEL_IDS = ["Master", "Slave1", "Slave2"]
# 全局统一的哈希对象
hash_func = hashlib.new('sha256')

############################################### 一些常用常数、函数的定义(尽量别修改) ############################## 完成
# 获取 basedir 下的子目录列表
def getsubdir(basedir):
    subdirs = [d for d in os.listdir(basedir) 
        if os.path.isdir(os.path.join(basedir, d)) and not d.startswith('.') ]
    return sorted(subdirs)

# 定义获取文件的函数
def getfiles(basedir):
    files = [f for f in os.listdir(basedir) 
        if os.path.isfile(os.path.join(basedir, f)) and not f.startswith('.')]
    return files

# 根据 filename 文件的文件内容计算 hash
def calculate_file_hash(filename):
    try:
        # 读取整个文件内容
        with open(filename, 'rb') as f:
            content = f.read()
            hash_func.update(content)
        # 返回哈希值的十六进制字符串
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error processing file {filename}: {e}")
        return None

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

###################### 2. 把 PARALLEL_IDS 下所有 IDS 的 queues 整合到一个 大 queue 里 ########################## 完成

# 一个全局变量，被所有并行任务共享，标识已经完成的任务数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

# 被并行执行的函数 --------------------------------------------------------------- start 
def unique_files(FUZZER, TARGET, PROGRAM, TIME):
    # 若 unique dir 已存在，删除，不存在，不报错
    unique_dir_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/queue"
    try:
        if os.path.exists(unique_dir_path):
            shutil.rmtree(unique_dir_path)
            print(f"Directory '{path}' removed successfully.")
        else:
            pass
    except Exception as e:
        print(f"Failed to remove directory: {e}")
    # 创建一个 unique dir
    # mkdir unique dir
    try:
        os.makedirs(unique_dir_path, exist_ok=False)
    except Exception as e:
        print(f"Failed to create directory '{unique_dir_path}': {e}")

    # 创建 hashpool，用来唯一化文件
    hashpool = {}

    # 遍历所有的文件，筛去一部分，计算 hash，若有重复 hash，保留时间上最小的文件，时间相同则按照 PARALLEL_IDS 顺序保留
    for parallel_id in PARALLEL_IDS:
        # 当前这个 PROGRAM-FUZZER-TIME 所对应的 plot_data 文件路径
        queue_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/" + parallel_id + "/queue"
        # 读取所有文件，仅仅保留有 time:(\d+),execs:(\d+) 的文件
        allfiles = getfiles(queue_path)
        pattern = r"time:(\d+),execs:(\d+),"
        # 遍历所有的文件，筛去一部分，计算 hash，若有重复 hash，保留时间上最小的文件，时间相同则按照 PARALLEL_IDS 顺序保留
        for file in allfiles:
            match = re.search(pattern, file)
            # 筛去没有 "time:(\d+),execs:(\d+)," 的文件
            if not match:
                continue
            time_val = int(match.group(1))  # 提取 time
            execs_val = int(match.group(2))  # 提取 execs
            file_path = queue_path + "/" + file
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                if file_hash not in hashpool:
                    hashpool[file_hash] = {}
                    hashpool[file_hash]["time"] = time_val
                    hashpool[file_hash]["execs"] = execs_val
                    hashpool[file_hash]["filepath"] = file_path
                else:
                    if time_val < hashpool[file_hash]["time"]:
                        hashpool[file_hash]["time"] = time_val
                        hashpool[file_hash]["execs"] = execs_val
                        hashpool[file_hash]["filepath"] = file_path
            else:
                print(f"Failed to process {file_path}.")

    # 遍历 hashpool，拷贝 hashpool 中的所有文件到 unique dir 中
    for hashval in hashpool:
        try:
            # 拷贝文件
            shutil.copy(hashpool[hashval]["filepath"], unique_dir_path)
            # print(f"File '{str(hashpool[hashval]["filepath"])}' copied to '{unique_dir_path}' successfully.")
        except Exception as e:
            print(f"Failed to copy file: {e}")

    # 打印信息，表示这个数据收集任务已完成
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME)
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

for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
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

                for TIME in TIMES:
                    result = pool.apply_async(unique_files, (FUZZER, TARGET, PROGRAM, TIME))
                    task_count += 1
                    results.append(result)

# 打印看看一共有多少个并行任务在运行
print(f"================== There are {len(results)} data collect tasks in total ==================")
sys.stdout.flush()

# 等待所有并行任务结束
for result in results:
    result.wait()

