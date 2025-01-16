import sys
import pandas as pd

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### 完成 
verify_environment()

######################################## 2. 并行读取绘图所需数据 (plot_data) ####################################
# 被并行执行的函数 --------------------------------------------------------------- start 
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME, parallel_id):
    # 当前这个 PROGRAM-FUZZER-TIME 所对应的 plot_data 文件路径
    plot_data_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/" + parallel_id + "/plot_data"
    # plot_data 是 csv 格式的，所以我们可以使用 pandas.DataFrame 的 csv API 读取它
    df = pd.read_csv(plot_data_path)
    # 把所有列表的首尾空白字符去掉
    df.columns = df.columns.str.strip()

    # 打印信息，表示这个数据收集任务已完成
    with FINISHED_TASKS.get_lock():
        FINISHED_TASKS.value += 1
        print(f"{FINISHED_TASKS.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME}-{parallel_id} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME, parallel_id, df)
# 被并行执行的函数 --------------------------------------------------------------- end

results = parallel_framework(collect_data_worker)

############################################### 3. 绘制 throughput_time 图    ################################################## 完成
draw_time("execs_per_sec", "execs_per_sec", False, results)



