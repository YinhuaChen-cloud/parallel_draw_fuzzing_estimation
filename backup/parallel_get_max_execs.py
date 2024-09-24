import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess

# CHANGE: ==== start
FUZZERS = ["aflplusplus", "path_fuzzer_original_k_1", "path_fuzzer_original_k_2", "path_fuzzer_original_k_4", "path_fuzzer_original_k_8"]
REPEAT = 3
# CHANGE: ==== end

# 用来记录已经完成的数据收集任务的数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

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

"""用来收集 seed_time 数据的工作函数"""
def max_execs_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    max_execs = -1
    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    queuedir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"

    files = getfiles(crashdir)
    for crash_file in files:
        matches = re.findall(r"execs:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            crash_execs = int(matches[0])
            if max_execs < crash_execs:
                max_execs = crash_execs

    files = getfiles(queuedir)
    for seed_file in files:
        matches = re.findall(r"execs:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:
            seed_execs = int(matches[0])
            if max_execs < seed_execs:
                max_execs = seed_execs

    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, max_execs)

# CHANGE: 这里根据不同的数据收集任务需要改变
"""总工作函数"""
def worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    return max_execs_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count)

def main():
    # NOTE: 判断当前文件夹是不是名为 cache =======================
    current_directory = os.getcwd()
    directory_name = os.path.basename(current_directory)
    assert(directory_name == "cache")

    # NOTE: 断言：FUZZERS 中包含的 fuzzers，都出现在下面 =========
    FUZZERS_real = getsubdir(current_directory)
    for fuzzer in FUZZERS:
        assert(fuzzer in FUZZERS_real)

    # NOTE: 检验是否所有 FUZZERS 下的 TARGETS 都是一样的 =========
    TARGETS_list = []
    for FUZZER in FUZZERS:
        TARGETS_list.append(getsubdir(FUZZER))

    for i in range(len(TARGETS_list)):
        assert(TARGETS_list[i] == TARGETS_list[0])

    TARGETS = TARGETS_list[0]
    # 去掉包含 "libsndfile" 的元素
    TARGETS = [target for target in TARGETS if "libsndfile" not in target]

    # NOTE: 检验是否所有 PROGRAMS 都一样 ==========================
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

    # NOTE: 为多线程收集数据做的一些准备
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
            for TARGET in TARGETS:

                path = FUZZER + "/" + TARGET
                thePROGRAMS = getsubdir(path)

                for thePROGRAM in thePROGRAMS:
                    if thePROGRAM != PROGRAM:
                        continue
                    path = FUZZER + "/" + TARGET + "/" + thePROGRAM
                    TIMES = getsubdir(path)
                    assert(len(TIMES) == REPEAT)

                    for TIME in TIMES:
                        assert(int(TIME) < REPEAT)

                    for TIME in TIMES:
                        result = pool.apply_async(worker, (FUZZER, TARGET, thePROGRAM, TIME, task_count))
                        task_count += 1
                        results.append(result)

    # 等待所有异步任务完成
    print(f"================== There are {len(results)} data collect tasks in total ==================")
    sys.stdout.flush()
    for result in results:
        result.wait()

    max_execs = -1
    for result in results:
        fuzz_result = result.get()
        the_execs = fuzz_result[4]
        if max_execs < the_execs:
            max_execs = the_execs
    print("max_execs = " + str(max_execs))

if __name__ == '__main__':
    main()


