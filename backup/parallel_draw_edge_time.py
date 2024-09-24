import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess

# LAVAM commands
# afl-fuzz -i corpus/base64 -o findings -m none -c cmplog/base64 -d -- afl/base64 -d @@
# afl-fuzz -i corpus/md5sum -o findings -m none -c cmplog/md5sum -d -- afl/md5sum -c @@
# afl-fuzz -i corpus/uniq -o findings -m none -c cmplog/uniq -d -- afl/uniq @@
# afl-fuzz -i corpus/who -o findings -m none -c cmplog/who -d -- afl/who @@
# MAGMA commands
# afl-fuzz -i corpus/exif -o findings -m none -c cmplog/exif -d -- afl/exif -
# afl-fuzz -i corpus/libpng_read_fuzzer -o findings -m none -c cmplog/libpng_read_fuzzer -d -- afl/libpng_read_fuzzer -
program_args = {
        "base64": "-d",        
        "md5sum": "-c",        
        "uniq": "",        
        "who": "",        
        "exif": "",        
        "libpng_read_fuzzer": "",        
}

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'mapfile', '-m', 'none', '-e', '--', 'PUT']

# 这个函数的目的：使用 afl-showmap 获取输入文件 filename 对程序 put 触发的 edges 合集，存放于字典中
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
# 参数 mapfile: edgemap 的文件实际路径
def getEdges(put, program, filename, mapfile):
    triggered_edges_set = {}
    command = copy.deepcopy(base_command)
    command[-1] = put
    assert(program_args[program] is not None)
    if program_args[program]:
        command.append(program_args[program])
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
# CHANGE: 配置，这里经常要改变 ============================== start
TOTAL_TIME = 72 # 单位小时
SPLIT_UNIT = 1 # 每隔 1 小时
FUZZERS = ["aflplusplus", "path_fuzzer_original_k_1", "path_fuzzer_original_k_2", "path_fuzzer_original_k_4", "path_fuzzer_original_k_8"]
REPEAT = 3 # 重复次数为 3
# CHANGE: 配置，这里经常要改变 ============================== end
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) # 分隔数量

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

"""用来收集 edge_execs 数据的工作函数"""
def edge_execs_worker(FUZZER, TARGET, thePROGRAM, TIME):
    pass

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
            # NOTE: 时间转换
            crash_time = int(matches[0])
            # print(crash_time)
            # 先转为秒
            crash_time /= 1000
            # 再转为分
            crash_time /= 60
            # 向下取整
            crash_time = int(crash_time)
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
            # 时间转换
            seed_time = int(matches[0])
            # 先转为秒
            seed_time /= 1000
            # 再转为分
            seed_time /= 60
            # 向下取整
            seed_time = int(seed_time)
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

"""用来收集 bug_execs 数据的工作函数"""
def bug_execs_worker(FUZZER, TARGET, thePROGRAM, TIME):
    pass

"""用来收集 bug_time 数据的工作函数"""
def bug_time_worker(FUZZER, TARGET, thePROGRAM, TIME):
    pass

"""用来收集 seed_execs 数据的工作函数"""
def seed_execs_worker(FUZZER, TARGET, thePROGRAM, TIME):
    pass

"""用来收集 seed_time 数据的工作函数"""
def seed_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    seed_time_slot = [0] * SPLIT_NUM
    path = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    files = getfiles(path)
    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:
            seed_time = int(matches[0])
            # 先转为秒
            seed_time /= 1000
            # 再转为分
            seed_time /= 60
            # 再转为小时
            seed_time /= 60
            # 向下取整
            seed_time = int(seed_time)
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

"""用来收集 crash_execs 数据的工作函数"""
def crash_execs_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    pass

"""用来收集 crash_time 数据的工作函数"""
def crash_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    crash_time_slot = [0] * SPLIT_NUM
    path = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    files = getfiles(path)
    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            crash_time = int(matches[0])
            # 先转为秒
            crash_time /= 1000
            # 再转为分
            crash_time /= 60
            # 再转为小时
            crash_time /= 60
            # 向下取整
            crash_time = int(crash_time)
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
    return crash_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count)

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
            # 开始绘图 
            x = [ i+1 for i in range(SPLIT_NUM) ]
            y = result_time_slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 添加标题和标签 CHANGE:
        plt.title(PROGRAM + ' crash-time graph')
        plt.xlabel('time (h)')
        plt.ylabel('# crashes')
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig('crash_time_' + PROGRAM + '_original.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'

    print("total " + str(len(results)) + " fuzzing result collect tasks")
    sys.stdout.flush()

    # 要结束了
    pool.close()
    pool.join()
    exit(0)

if __name__ == '__main__':
    main()


