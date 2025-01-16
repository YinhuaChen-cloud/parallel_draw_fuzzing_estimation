import os
import sys
import shutil

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

######################################## 2. 定义删除 unique crash/queue 的并行函数 ############################## checked
# 被并行执行的函数 --------------------------------------------------------------- start 
def delete_unique(FUZZER, TARGET, PROGRAM, TIME):
    # 若 unique dir 已存在，删除，不存在，不报错
    unique_dir_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/"
    try:
        if os.path.exists(unique_dir_path):
            shutil.rmtree(unique_dir_path)
            print(f"Directory '{unique_dir_path}' removed successfully.")
        else:
            print(f"Directory '{unique_dir_path}' does not exist. No action taken.")
    except Exception as e:
        print(f"Failed to remove directory: {e}")

    # 打印信息，表示这个数据收集任务已完成
    with FINISHED_TASKS.get_lock():
        FINISHED_TASKS.value += 1
        print(f"{FINISHED_TASKS.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME)
# 被并行执行的函数 --------------------------------------------------------------- end

######################################## 3. 执行 delete unique #################################### checked
results = parallel_framework(delete_unique, need_parallel_id=False)

