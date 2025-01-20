import re
import sys
import copy
import pandas as pd
import subprocess

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

######################################## 2. 运行出 bugs 所需的命令 ############################################### checked
# 这些 program_args 表示需要各个 PUT 在单独运行某些种子时，需要添加的参数
program_args = {
    # lAVAM
    "base64": ["-d", "INPUT_FILE"],        
    "md5sum": ["-c", "INPUT_FILE"],        
    "uniq": ["INPUT_FILE"],        
    "who": ["INPUT_FILE"],        
}

# 在 timeout 限制下来运行一个命令
def sub_run(cmd, timeout):
    try: 
         r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
         return r
    except subprocess.TimeoutExpired:
        print("time out")
        return None

# 获取某个文件能触发的 bugs 编号
# 这个函数的目的：获取 filename 能在 program 上触发的 bugs dict
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PUT 对应的 PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
def getBugs(put, program, filename):
    # 断言：某参数已经齐全
    assert(program_args[program] is not None)
    # 构建命令
    cmd = [put]
    for arg in program_args[program]:
        if arg == "INPUT_FILE":
            cmd.append(filename)
        else:
            cmd.append(arg)
    print(cmd)
    # 6秒限制超时，运行该命令
    r = sub_run(cmd, 6)
    # 如果没有输出，返回空字典
    if r is None:
        return {}
    # 如果有输出，那么检查是否 trigger 了注入的 bugs，返回一个字典
    bug_dict = {}
    out = r.stdout.split(b'\n')
    for line in out:
        # 如果 trigger 了 bugs，那么存入一个列表，最后返回
        if line.startswith(b"Successfully triggered bug"):
            dot = line.split(b',')[0]
            cur_id = int(dot[27:])
            if cur_id not in bug_dict:                        
                bug_dict[cur_id] = 1
    return bug_dict

########################################### 3. 并行获取 bugs 所需数据 ###################################### checked
# 被并行执行的函数 --------------------------------------------------------------- start
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME):

    print(f"start {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
    sys.stdout.flush()

    with TASK_COUNT.get_lock():
        TASK_COUNT.value += 1
        print(f"{TASK_COUNT.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
        task_count = TASK_COUNT.value

    df = None
    try:
        # 第一步：把 crash 所有文件读出来，按照时间排序
        # 第二步：按照排序的顺序，逐个使用 getBugs 获取触发的 bug_dict
        # 第三步，根据第二步得到的数据，构造一个 dataFrame，随后返回这个 dataframe

        # 无论何时，用来计算触发 edges 的 PUT 都是同一个
        put = "clang" + "/" + TARGET + "/" + PROGRAM + "/0/afl/" + PROGRAM

        # 第一步：把 crash 所有文件读出来，按照时间排序
        crashdir = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/crashes/"
        crashfiles = getfiles(crashdir)
        pattern = r"time:(\d+),execs:(\d+),"
        inputfile_list = []
        for file in crashfiles:
            match = re.search(pattern, file)
            assert(match)
            time_val = int(match.group(1))  # 提取 time
            execs_val = int(match.group(2))  # 提取 execs
            # 先转为秒
            time_val /= 1000
            # 构建为 InputFile 对象
            inputfile = InputFile(time=time_val, execs=execs_val, filepath=(crashdir + file))
            inputfile_list.append(inputfile)
        # 第一步，按照 time 排序
        inputfile_list.sort(key=lambda x : x.time)

        # 第二步：按照排序的顺序，逐个使用 getBugs 获取触发的 bug_dict
        # class 包含：time, execs, filepath, triggered_edges
        bug_set_accumulate = {}
        for inputfile in inputfile_list:
            bug_dict = getBugs(put, PROGRAM, inputfile.filepath)
            bug_set_accumulate.update(bug_dict)
            inputfile.bugs = len(bug_set_accumulate)

        # 第三步，根据第二步得到的数据，构造一个 dataFrame，随后返回这个 dataframe
        time_list  = []
        execs_list = []
        bugs_list = []
        for inputfile in inputfile_list:
            time_list.append(inputfile.time)
            execs_list.append(inputfile.execs)
            bugs_list.append(inputfile.bugs)
        data = {
            "# relative_time" : time_list,
            "total_execs"     : execs_list,
            "bugs_found"      : bugs_list,
        }
        df = pd.DataFrame(data)
        df = df.sort_values("# relative_time")
        # 按 '# relative_time' 分组，找到每组的最大 'total_execs'
        df['total_execs'] = df.groupby('# relative_time')['total_execs'].transform('max')
        # 按 '# relative_time' 分组，找到每组的最大 'edges_found'
        df['bugs_found'] = df.groupby('# relative_time')['bugs_found'].transform('max')
        # 按 '# relative_time' 列去重，保留第一行（默认）
        df = df.drop_duplicates(subset='# relative_time', keep='first')

        # 打印信息，表示这个数据收集任务已完成
        with FINISHED_TASKS.get_lock():
            FINISHED_TASKS.value += 1
            print(f"{FINISHED_TASKS.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
            sys.stdout.flush()
    except Exception as e:
        print(f"Exception caught in main process: {e}")
    assert(df is not None)
    return (FUZZER, TARGET, PROGRAM, TIME, df)
# 被并行执行的函数 --------------------------------------------------------------- end

############################################### 4. 绘制 bug 图   ################################################## checked
results = parallel_framework(collect_data_worker, need_parallel_id=False)
max_execs_dict = get_max_execs_dict(results)   
draw_time("bug", "bugs_found", True, results, need_parallel_id=False)
draw_execs("bug", "bugs_found", True, results, max_execs_dict, need_parallel_id=False)

