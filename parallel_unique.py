import os
import re
import sys
import shutil

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

######################################## 2. 定义 unique crash/queue 的并行函数 #################################### checked 
# 被并行执行的函数 --------------------------------------------------------------- start 
# 该函数根据 CRASH_OR_QUEUE 来决定为哪个文件夹做去重
CRASH_OR_QUEUE = None
def unique_files(FUZZER, TARGET, PROGRAM, TIME):
    # 创建一个 unique dir
    # mkdir -p unique dir
    assert(CRASH_OR_QUEUE)
    unique_dir_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/" + CRASH_OR_QUEUE
    try:
        os.makedirs(unique_dir_path, exist_ok=True)
    except Exception as e:
        print(f"Failed to create directory '{unique_dir_path}': {e}")

    # 创建 hashpool，用来唯一化文件
    hashpool = {}

    # 遍历所有的文件，筛去一部分，计算 hash，若有重复 hash，保留时间上最小的文件，时间相同则按照 PARALLEL_IDS 顺序保留
    for parallel_id in PARALLEL_IDS:
        # 当前这个 PROGRAM-FUZZER-TIME 所对应的 plot_data 文件路径
        crahs_queue_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/" + parallel_id + "/" + CRASH_OR_QUEUE
        # 读取所有文件，仅仅保留有 time:(\d+),execs:(\d+) 的文件
        allfiles = getfiles(crahs_queue_path)
        pattern = r"time:(\d+),execs:(\d+),"
        # 遍历所有的文件，筛去一部分，计算 hash，若有重复 hash，保留时间上最小的文件，时间相同则按照 PARALLEL_IDS 顺序保留
        for file in allfiles:
            match = re.search(pattern, file)
            # 筛去没有 "time:(\d+),execs:(\d+)," 的文件
            if not match:
                continue
            time_val = int(match.group(1))  # 提取 time
            execs_val = int(match.group(2))  # 提取 execs
            file_path = crahs_queue_path + "/" + file
            file_hash = calculate_file_hash(file_path)
			assert(file_hash)
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
    with FINISHED_TASKS.get_lock():
        FINISHED_TASKS.value += 1
        print(f"{FINISHED_TASKS.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME)
# 被并行执行的函数 --------------------------------------------------------------- end

######################################## 3. 执行 unique crash/queue #################################### checked
CRASH_OR_QUEUE = "crashes"
results = parallel_framework(unique_files, need_parallel_id=False)
CRASH_OR_QUEUE = "queue"
results = parallel_framework(unique_files, need_parallel_id=False)

