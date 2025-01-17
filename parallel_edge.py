import re
import sys
import copy
import pandas as pd
import math
import subprocess

from parallel_common import *

######################################## 1. 验证 fuzzing result 是否有异常 ###################################### checked
verify_environment()

######################################## 2. 获取 edges 所需的配置 ############################################### checked
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'MAPFILE', '-m', 'none', '-e', '--', 'PUT']

# 这些 program_args 表示需要各个 PUT 在单独运行某些种子时，需要添加的参数
edge_program_args = {
    # lAVAM
    "base64": ["-d", "INPUT_FILE"],        
    "md5sum": ["-c", "INPUT_FILE"],        
    "uniq": ["INPUT_FILE"],        
    "who": ["INPUT_FILE"],        
}

# 获取某个文件能触发的 edges 编号
# 这个函数的目的：使用 afl-showmap 获取输入文件 filename 对程序 put 触发的 edges 合集，通过一个字典返回
# 参数 put: PUT 可执行文件的实际路径
# 参数 program: PUT 对应的 PROGRAM 的字符串名称
# 参数 filename: 输入文件的实际路径
# 参数 mapfile: 用来存放 edgemap 的文件路径
# task_count: 表示这是第几个并行任务
def getEdges(put, program, filename, mapfile, task_count):
    # triggered_edges_set 包含 filename 能触发的 edges 的编号
    triggered_edges_set = {}
    # 深拷贝
    command = copy.deepcopy(base_command)
    # 把 PUT占位符 替换成实际的 put 文件路径
    command[-1] = put
    # 把 MAPFILE 占位符 替换成实际的 mapfile 文件路径
    command[5] = mapfile
    # 断言：对应 PROGRAM 的参数在字典中一定存在
    assert(edge_program_args[program] is not None)
    # 往命令行列表添加 PROGRAM 参数
    for arg in edge_program_args[program]:
        if arg == "INPUT_FILE":
            command.append(filename)
        elif arg == "TMPOUT":
            command.append("tmp.out." + str(task_count))
        else:
            command.append(arg)

    # 如果当前正在处理的 PROGRAM 是 tiffcp，那么需要做一些特殊处理。
    # 原因是 tiffcp 不能识别 AFL++ 的 crash 文件命名方式，所以需要对 AFL++ 的 crash 文件重命名
    result = None
    if program == "tiffcp":
        tmpcmd = ["cp", filename, "deadbeef_bug." + str(task_count)]
        try:
            result = subprocess.run(tmpcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
        except:
            print("Unexpected error at tiffcp: " + filename)
            print("result.stdout =============================")
            print(result.stdout)
            print("result.stderr =============================")
            print(result.stderr)
            assert(0)
        # 重命名成功后，把 command 中的输入文件替换成重命名后的文件
        command[12] = tmpcmd[2]

    # 执行 command，产生 mapfile
    try: 
        print("=============== before =============")
        print(command)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
        print("=============== after =============")
    except:
        print("result.stdout =============================")
        print(result.stdout)
        print("result.stderr =============================")
        print(result.stderr)
        print("===== or TIME OUT, filename = " + filename)
        assert(0)

    # # 打印命令的标准输出，这个一般在 DEBUG 时用
    # print("标准输出:")
    # print(result.stdout)

    # 打开产生的 mapfile 文件，把触发的 edges 存入 triggered_edges_set
    with open(mapfile, 'r') as the_mapfile:
        for line in the_mapfile:
            # 去除每行的前后白字符
            line = line.strip()
            # 分割每行的字符串和整数
            if ':' in line:
                key, value = line.split(':', 1)
                # 存入字典
                triggered_edges_set[key] = 1

    # 返回字典
    return triggered_edges_set 

########################################### 3. 并行获取 edges 所需数据 ###################################### checked
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
        # 第一步：把 crash 和 queue 下所有文件读取出来，去掉包含 "+pat" 的文件，随后按照 "time" 排序
        # 加个 assert()，表示一个列表里绝对没有两个文件的 time 是相等的
        # 第二步：按照排序的顺序，逐个使用 getEdges 获取触发的 edges，记录数量，维护一个 class
        # class 包含：time, execs, triggered_edges
        # 第三步，根据第二部得到的 class 列表，构造一个 dataFrame，随后返回这个 dataframe

        # 无论何时，用来计算触发 edges 的 PUT 都是同一个
        put = "aflplusplus" + "/" + TARGET + "/" + PROGRAM + "/0/afl/" + PROGRAM

        # 第一步：把 crash 和 queue 下所有文件读取出来，去掉包含 "+pat" 的文件，随后按照 "time" 排序
        # 加个 assert()，表示一个列表里绝对没有两个文件的 time 是相等的
        # 读取 crash 和 queue 文件夹下所有文件
        queuedir = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/unique/queue/"
        queuefiles = getfiles(queuedir)
        # 去掉包含 "+pat" 文件，剩余在 unique 文件夹中的文件必定带有 time:(\d+),execs:(\d+)
        filterfiles = []
        pattern = r"time:(\d+),execs:(\d+),"
        # 再从 queuefiles 中过滤
        for file in queuefiles:
            pat_match = re.findall(r"\+pat", file)
            assert(len(pat_match) < 2)
            if pat_match:
                continue
            match = re.search(pattern, file)
            assert(match)
            time_val = int(match.group(1))  # 提取 time
            execs_val = int(match.group(2))  # 提取 execs
            # 先转为秒
            time_val /= 1000
            # # 再把时间转为分钟，这里使用向上取整，因为我们希望能保留 time = 0 和 execs = 0，其它都算作1分钟的
            # time_val = math.ceil(time_val / 60)
            # 构建为 InputFile 对象
            inputfile = InputFile(time=time_val, execs=execs_val, filepath=(queuedir + file))
            filterfiles.append(inputfile)
        # 第一步，按照 time 排序
        filterfiles.sort(key=lambda x : x.time)

        # 第二步，按照时间排序后，挨个文件获取 edges_count，时间为分钟，后续再归并
        # class 包含：time, execs, filepath, triggered_edges
        edge_set_accumulate = {}
        for inputfile in filterfiles:
            edge_set = getEdges(put, PROGRAM, inputfile.filepath, "mapfile" + str(task_count), task_count)
            edge_set_accumulate.update(edge_set)
            inputfile.edges = len(edge_set_accumulate)

        # 第三步，根据第二部得到的 class 列表，构造一个 dataFrame，随后返回这个 dataframe
        time_list  = []
        execs_list = []
        edges_list = []
        for inputfile in filterfiles:
            time_list.append(inputfile.time)
            execs_list.append(inputfile.execs)
            edges_list.append(inputfile.edges)
        data = {
            "# relative_time" : time_list,
            "total_execs"     : execs_list,
            "edges_found"     : edges_list,
        }
        df = pd.DataFrame(data)
        # 按 '# relative_time' 分组，找到每组的最大 'total_execs'
        df['total_execs'] = df.groupby('# relative_time')['total_execs'].transform('max')
        # 按 '# relative_time' 分组，找到每组的最大 'edges_found'
        df['edges_found'] = df.groupby('# relative_time')['edges_found'].transform('max')
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

############################################### 4. 绘制 edge 图   ################################################## checked
results = parallel_framework(collect_data_worker, need_parallel_id=False)
max_execs_dict = get_max_execs_dict(results)   
draw_time("edge", "edges_found", True, results, need_parallel_id=False)
draw_execs("edge", "edges_found", True, results, max_execs_dict, need_parallel_id=False)

