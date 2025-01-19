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

########################################### 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

########################################### 2. 并行读取绘图所需数据 (DIRNAME) ###################################### checked
# 被并行执行的函数 --------------------------------------------------------------- start 
DIRNAME = None
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME):
    # 返回一个 DataFrame
    InputFile_list = []
    queue_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/" + DIRNAME
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
        inputfile = InputFile(time=time_val, execs=execs_val, filepath="")
        InputFile_list.append(inputfile)
    # 按照时间排序
    InputFile_list.sort(key=lambda x : x.time)
    # 构建 DataFrame
    time_list = []
    execs_list = []
    file_count_list = []
    file_count = 0
    for inputfile in InputFile_list:
        time_list.append(inputfile.time)
        execs_list.append(inputfile.execs)
        file_count += 1
        file_count_list.append(file_count)
    data = {
        "# relative_time" : time_list,
        "total_execs"     : execs_list,
        "file_count"      : file_count_list,
    }
    df = pd.DataFrame(data)
    # 按 '# relative_time' 分组，找到每组的最大 'total_execs'
    df['total_execs'] = df.groupby('# relative_time')['total_execs'].transform('max')
    # 按 '# relative_time' 分组，找到每组的最大 'file_count'
    df['file_count'] = df.groupby('# relative_time')['file_count'].transform('max')
    # 按 '# relative_time' 列去重，保留第一行（默认）
    df = df.drop_duplicates(subset='# relative_time', keep='first')

    # 打印信息，表示这个数据收集任务已完成
    with FINISHED_TASKS.get_lock():
        FINISHED_TASKS.value += 1
        print(f"{FINISHED_TASKS.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME, df)
# 被并行执行的函数 --------------------------------------------------------------- end

############################################### 3. 绘制 crash 图   ################################################## checked
DIRNAME = "crashes"
results = parallel_framework(collect_data_worker, need_parallel_id=False)
max_execs_dict = get_max_execs_dict(results)   
draw_time("crash", "file_count", True, results, need_parallel_id=False)
draw_execs("crash", "file_count", True, results, max_execs_dict, need_parallel_id=False)

############################################### 4. 绘制 seed 图    ################################################## checked
DIRNAME = "queue"
results = parallel_framework(collect_data_worker, need_parallel_id=False)
max_execs_dict = get_max_execs_dict(results)   
draw_time("seed", "file_count", True, results, need_parallel_id=False)
draw_execs("seed", "file_count", True, results, max_execs_dict, need_parallel_id=False)


