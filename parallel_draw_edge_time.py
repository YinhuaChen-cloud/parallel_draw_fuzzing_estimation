import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess
import math
from datetime import datetime

############################################### 0. 配置部分         ##################################################
TOTAL_TIME = 72 * 60 # 单位分钟
SPLIT_UNIT = 1  # 每隔 1 分钟
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量
# # 比较所有 fuzzers 的情况
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_empty_path_k_2", "path_fuzzer_empty_path_k_4", "path_fuzzer_empty_path_k_8", \
    # "path_fuzzer_full_path_k_1", "path_fuzzer_full_path_k_2", "path_fuzzer_full_path_k_4", "path_fuzzer_full_path_k_8"]
# 只比较 k=1 和 AFL++ 的情况
FUZZERS = ["aflplusplus", "path_fuzzer_empty_path_k_1", "path_fuzzer_full_path_k_1"]
TARGETS = ["php", "libsndfile", "libtiff", "sqlite3", "lua", "libpng", "libxml2"]
# FUZZERS = ["aflplusplus", "path_fuzzer_empty_path", "path_fuzzer_full_path", "cov_trans_fuzzer_empty_path", "cov_trans_fuzzer_full_path"]
# TARGETS = ["base64", "md5sum", "uniq", "who"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# WORKDIR = "workdir_1d_REPEAT4_LAVAM"
# 重复次数
REPEAT=2
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_only1"
# 是否把 "+pat" 种子计入 edge_time 绘图中
plusPAT = False
############################################### 1. 一些函数的定义    ##################################################

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

# 这里的 program_args 可以是为了找 edges，也可以是为了找 bugs
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
        # TODO: 后续再加三个
}

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
# singularity run ./afl-showmap.sif /magma/fuzzers/aflplusplus/repo/afl-showmap -o mapfile -m none -e -- ....
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'mapfile', '-m', 'none', '-e', '--', 'PUT']

# 转化时间为正确单位的函数
def ms_to_min(original_time):
    # 先转为秒
    original_time /= 1000
    # 再转为分
    original_time /= 60
    # 向上取整
    original_time = math.ceil(original_time)
    return original_time

# 这个函数的目的：使用 afl-showmap 获取输入文件 filename 对程序 put 触发的 edges 合集，存放于字典中
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
# 参数 mapfile: edgemap 的文件实际路径
def getEdges(put, program, filename, mapfile, task_count):
    triggered_edges_set = {}
    command = copy.deepcopy(base_command)
    command[-1] = put
    command[5] = mapfile
    assert(edge_program_args[program] is not None)
    for arg in edge_program_args[program]:
        if arg == "INPUT_FILE":
            command.append(filename)
        elif arg == "TMPOUT":
            command.append("tmp.out." + str(task_count))
        else:
            command.append(arg)

    if program == "tiffcp":
        tmpcmd = ["cp", filename, "deadbeef_bug." + str(task_count)]
        try:
            result = subprocess.run(tmpcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
        except:
            print("Unexpected error at tiffcp: " + filename)
            assert(0)
        command[12] = tmpcmd[2]

    try: 
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5)
    except subprocess.TimeoutExpired:
        print("TIME OUT, filename = " + filename)

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

"""用来收集 edge_time 数据的工作函数"""
def edge_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    edge_time_slot = [0] * SPLIT_NUM
    edge_time_slot_dict = [{} for _ in range(SPLIT_NUM)] 
    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    queuedir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    # 无论何时，用来计算触发 edges 的 PUT 都是同一个
    put = "aflplusplus" + "/" + TARGET + "/" + thePROGRAM + "/0/afl/" + thePROGRAM

    # 获取当前时间并以自定义格式显示
    files = getfiles(crashdir)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("curtime:" + str(current_time) + " PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(crash_files) = " + str(len(files)) + " taskcount = " + str(task_count))
    sys.stdout.flush()

    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            # 如果是 +pat 种子，那么跳过，因为它必不增加 edge-cov 
            pat_matches = re.findall(r"\+pat", crash_file)
            assert(len(pat_matches) < 2)
            if pat_matches and (not plusPAT):
                continue

            crash_time = ms_to_min(int(matches[0]))

            if crash_time < SPLIT_NUM:
                # NOTE: 计算这个单独文件触发的边缘字典
                triggered_edges_set = getEdges(put, thePROGRAM, crashdir + crash_file, "mapfile" + str(task_count), task_count)
                # 在边缘字典槽里更新
                edge_time_slot_dict[crash_time].update(triggered_edges_set)

    # 获取当前时间并以自定义格式显示
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("curtime:" + str(current_time) + " PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + " just finish collect crash data")
    sys.stdout.flush()

    # 再获取 seeds 的 edges
    files = getfiles(queuedir)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("curtime:" + str(current_time) + " PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(seedfiles) = " + str(len(files)) + " taskcount = " + str(task_count))
    sys.stdout.flush()

    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:
            # 如果是 +pat 种子，那么跳过，因为它必不增加 edge-cov 
            pat_matches = re.findall(r"\+pat", seed_file)
            assert(len(pat_matches) < 2)
            if pat_matches and (not plusPAT):
                continue

            seed_time = ms_to_min(int(matches[0]))

            if seed_time < SPLIT_NUM:
                # NOTE: 计算这个单独文件触发的边缘字典
                triggered_edges_set = getEdges(put, thePROGRAM, queuedir + seed_file, "mapfile" + str(task_count), task_count)
                # 在边缘字典槽里更新
                edge_time_slot_dict[seed_time].update(triggered_edges_set)

    # 获取当前时间并以自定义格式显示
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("curtime:" + str(current_time) + " PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + " just finish collect seed data")
    sys.stdout.flush()
                
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

# CHANGE: 这里根据不同的数据收集任务需要改变
"""总工作函数"""
def worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    return edge_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count)

def main():
    # NOTE: 判断当前文件夹是否正确 =======================
    current_directory = os.getcwd()
    directory_name = os.path.basename(current_directory)
    assert(directory_name == WORKDIR)

    # NOTE: 断言：FUZZERS 中包含的 fuzzers，都出现在下面 =========
    FUZZERS_real = getsubdir(current_directory)
    for fuzzer in FUZZERS:
        assert(fuzzer in FUZZERS_real)

    # NOTE: 检验是否所有 FUZZERS 都包含我们要绘制的那些 TARGETS
    # 先获取所有 FUZZERS 文件下的所有 TARGETS
    TARGETS_list = []
    for FUZZER in FUZZERS:
        TARGETS_list.append(getsubdir(FUZZER))

    for i in range(len(TARGETS_list)):
        for target in TARGETS:
            assert(target in TARGETS_list[i])

    # NOTE: 获取所有 PROGRAMS，同时检验是否所有 PROGRAMS 都一样 ==========================
    # 获取所有 FUZZERS 的 PROGRAMS
    PROGRAMS_list = []
    for FUZZER in FUZZERS:
        its_PROGRAMS = []
        for TARGET in TARGETS:
            path = FUZZER + "/" + TARGET
            its_PROGRAMS.append(getsubdir(path))
        its_PROGRAMS = [ item for sublist in its_PROGRAMS for item in sublist ]
        PROGRAMS_list.append(its_PROGRAMS)

    for i in range(len(PROGRAMS_list)):
        assert(PROGRAMS_list[i] == PROGRAMS_list[0])

    PROGRAMS = PROGRAMS_list[0]

    # NOTE: 为多线程收集数据做的一些准备 ===================================================
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
    # NOTE: 这里收集到的每个 RESULTS，都是一个 fuzzer-target-time 的 edge_time 数据，横轴是 time，纵轴是 edges
    print(f"================== There are {len(results)} data collect tasks in total ==================")
    sys.stdout.flush()
    for result in results:
        result.wait()

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
            # 求平均，向上取整
            result_time_slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    result_time_slot_avg[i] += result_time_slot[k][i]
                result_time_slot_avg[i] /= REPEAT
                result_time_slot_avg[i] = math.ceil(result_time_slot_avg[i])
            # 开始绘图  CHANGE:
            x = [ (i/60) for i in range(SPLIT_NUM) ]
            y = result_time_slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 添加标题和标签 CHANGE:
        # 注意：edges 最好使用 min 作为横轴单位！！！
        plt.title(PROGRAM + ' edge-time graph')
        plt.xlabel('time(h)')
        plt.ylabel('# edges')
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig('edge_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        print("finish drawing edge_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()

        plt.close()  # 关闭图形

    print("total " + str(len(results)) + " fuzzing result collect tasks")
    sys.stdout.flush()

    # 要结束了
    pool.close()
    pool.join()
    exit(0)

if __name__ == '__main__':
    main()


