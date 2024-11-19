import multiprocessing
import time
import os
import matplotlib.pyplot as plt
import re
import sys
import copy
import subprocess

############################################### 0. 配置部分         ##################################################
TOTAL_TIME = 12 * 60 # 单位分钟
FUZZERS = ["aflplusplus", "nopathreduction"]
TARGETS = ["base64", "md5sum", "uniq", "who", "libpng", "libsndfile", "php", "sqlite3", "lua", "libxml2", "libtiff", "openssl"]
# 表明这个脚本所运行的文件夹
WORKDIR = "cache"
# 重复次数
REPEAT=1
# 这次绘图命名的特殊后缀，比如 _empty or _full 之类的
SPECIFIC_SUFFIX = "_all"
# 决定绘制哪些图，不绘制哪些图
draw_configure = {
    "bug_time"     : True,
    "bug_execs"    : True,
}

############################################### 1. 一些常用常数、函数的定义(尽量别修改) ##############################
SPLIT_UNIT = 1
SPLIT_NUM = int(TOTAL_TIME / SPLIT_UNIT) + 1 # 绘图时，x 轴的有效点数量

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

######################################## 2. 验证 fuzzing result 是否有异常 ##################################################
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

############################################### 3. 并行读取绘图所需数据 (bug triggered) ##################################################
# 在 timeout 限制下来运行一个命令，这个函数通常用来查看一个 crash 触发了哪些 bug
def sub_run(cmd, timeout):
    try: 
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return r
    except subprocess.TimeoutExpired:
        print("time out")
        sys.stdout.flush()
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
bug_program_args = {
        # lAVAM
        "base64": "-d",        
        "md5sum": "-c",        
        "uniq": "",        
        "who": "",        
        # # MAGMA
        # "libpng_read_fuzzer": "",        
        # "sndfile_fuzzer": "",
        # "tiff_read_rgba_fuzzer": "",
        # "tiffcp": "-M",
        # "libxml2_xml_read_memory_fuzzer": "",
        # "xmllint": "--valid --oldxml10 --push --memory"
}

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'mapfile', '-m', 'none', '-e', '--', 'PUT']



# 一个全局变量，被所有并行任务共享，标识已经完成的任务数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

# 被并行执行的函数 --------------------------------------------------------------- start
def collect_data_worker(FUZZER, TARGET, PROGRAM, TIME, task_count):
    # 当前这个 PROGRAM-FUZZER-TIME 所对应的 plot_data 文件路径
    plot_data_path = FUZZER + "/" + TARGET + "/" + PROGRAM + "/" + TIME + "/findings/default/plot_data"
    # plot_data 是 csv 格式的，所以我们可以使用 pandas.DataFrame 的 csv API 读取它
    df = pd.read_csv(plot_data_path)
    # 把所有列表的首尾空白字符去掉
    df.columns = df.columns.str.strip()

    # 打印信息，表示这个数据收集任务已完成
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{PROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    # 返回存储数据的 DataFrame，也就是 df，前面的几个元素是为了标识这个 df 属于哪个 PROGRAM-FUZZER-TIME
    return (FUZZER, TARGET, PROGRAM, TIME, df)
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

# 为每一个 program-fuzzer-repeat_time 收集 plot_data 数据
for PROGRAM in PROGRAMS:
    for FUZZER in FUZZERS:
        # 收集这个 PROGRAM-FUZZER 的所有 REPEAT_times 的 plot_data 数据

        # 找到包含当前 PROGRAM 的 TARGETS
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

                # 分配一个 CPU cores，让它收集当前 PROGRAM-FUZZER-TIME 的 plot_data 信息，结果存放于 results 列表
                for TIME in TIMES:
                    result = pool.apply_async(collect_data_worker, (FUZZER, TARGET, PROGRAM, TIME, task_count))
                    task_count += 1
                    results.append(result)

# 打印看看一共有多少个并行任务在运行
print(f"================== There are {len(results)} data collect tasks in total ==================")
sys.stdout.flush()

# 等待所有并行任务结束
for result in results:
    result.wait()

############################################### 3. 统计各程序 max_execs   ##################################################
# 这一部分的目的，是为了确认各个 PROGRAM 的执行次数横轴图的最大执行次数
# 因为不同 FUZZERS 执行速率不一样，所以哪怕运行相同的时间，最后产生的最大执行次数可能差很多
# 我这里是取执行速率最慢的 FUZZERS 的最大执行次数，作为绘图的最大执行次数

# 这个字典的 key 是 PROGRAM, value 是该 PROGRAM 在所有 FUZZERS 中最小的 max_execs
max_execs_dict = {}

# 统计每个 PROGRAM 在所有 FUZZERS 中最小的 max_execs，存放于 max_execs_dict 中
for PROGRAM in PROGRAMS:
    # 找到当前 PROGRAM 在所有 FUZZERS 中最小的 max_execs
    max_execs = float('inf')
    for FUZZER in FUZZERS:
        # 在 results 列表中找到 当前 PROGRAM-FUZZER 的所有数据，存放于 dfs 列表中
        dfs = []
        for result in results:
            fuzz_result = result.get()
            if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                continue
            dfs.append(fuzz_result[4])
        # 收集完后，一共能收集到 REPEAT 个 df
        assert(len(dfs) == REPEAT)
        # 在 dfs 列表中找到最小的 max_execs
        for df in dfs:
            if df["total_execs"].max() < max_execs:
                max_execs = df["total_execs"].max() 
    # 把这个 PROGRAM 在所有实验中的最小的 max_execs 存放于 max_execs_dict 字典中
    max_execs_dict[PROGRAM] = max_execs

############################################### 4. 定义绘图函数   ##################################################
# name: 决定 y轴 和图的名字
# colname: df中和 y轴 相应那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？ (crash, seed 属于积累属性, Throughput 不属于)
# 或者说，种子数量、crash数量、bug 数量这些是可以积累的，但是 “速度” 是不可以积累的
# 路程是可以积累的，速度是不能积累的。学习的知识是可以积累的，学习的速度是不能积累的
# 这就是 “积累” 属性
def draw_time(name: str, colname: str, accumulate: bool):
    # 每一个 PROGRAM 绘制一张图 (FUZZERS 是这张图上的 legend)
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，储存在 dfs 列表中
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[4])
            # 验证 REPEAT 是否和 dfs 收集到的数量一致
            assert(len(dfs) == REPEAT)
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME 的 plot_data，可以绘制成一条线
            # 我们要对这些 df 的值取平均
            # slot_list 就是用来存放绘图数据数组的列表
            slot_list = []
            for df in dfs:
                # 用来绘图的数据数组
                slot = [0] * SPLIT_NUM
                # 因为是 draw_time 先给 df 按照时间排序排序
                df = df.sort_values("# relative_time")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    # 取得这一行的时间(单位：秒)
                    time_s = int(row["# relative_time"])
                    # 把时间转为分钟，随后放入 slot 中相应的位置
                    k = math.ceil(time_s / 60)
                    # 部分实验可能会运行超过规定的时间，我们把超过规定时间的数据忽略掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # 因为我们计算 k 是向上取整，所以元素0必须为0
                assert(slot[0] == 0)
                # 如果这个属性是 “积累属性”，那么就需要填补 slot 中为 0 的部分
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            # 验证，slot_list 的长度必须等于 REPEAT
            assert(len(slot_list) == REPEAT)
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
                slot_avg[i] = math.ceil(slot_avg[i])

            # 有了 slot_avg 就能绘图了
            # 开始绘图
            # x 轴以小时(h) 为单位，我们的 slot_avg 每一个下标都是分钟 min，所以这里要除以 60
            x = [ (i/60) for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 这个 PROPGRAM 绘制完毕后，要命名
        # 设置标题
        plt.title(PROGRAM + " " + name + '-time graph')
        # 设置 x 轴
        plt.xlabel('time(h)')
        # 设置 y 轴
        plt.ylabel('# ' + name)
        # 设置文件名和文件类型 (png, svg, pdf ....)
        plt.savefig(name + '_time_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg') 
        # 打印日志标识成功绘制这个图片
        print("finish drawing " + name + "_time_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()
        # 关闭图形，节约内存
        plt.close()  

    # 打印日志：成功绘制完某一类型的图片
    print("============================= finish drawing " + name + "_time graph part =============================")
    sys.stdout.flush()

# name: 决定 y轴 和图的名字
# colname: df中和 y轴 相应那一列的列名
# accumulate: 这一列是否属于 “积累” 属性？ (crash, seed 属于积累属性, Throughput 不属于)
# 或者说，种子数量、crash数量、bug 数量这些是可以积累的，但是 “速度” 是不可以积累的
# 路程是可以积累的，速度是不能积累的。学习的知识是可以积累的，学习的速度是不能积累的
# 这就是 “积累” 属性
def draw_execs(name: str, colname: str, accumulate: bool):
    # 每一个 PROGRAM 绘制一张图 (FUZZERS 是这张图上的 legend)
    for PROGRAM in PROGRAMS:

        plt.figure()  # 创建一个新的图形
        # 获取这个程序的 max_execs，并计算 execs_unit
        # 后续每一下标表示 “经历了一个 execs_unit” 这么多的执行次数
        max_execs = max_execs_dict[PROGRAM]
        execs_unit = (max_execs / int(TOTAL_TIME / SPLIT_UNIT))

        for FUZZER in FUZZERS:
            # 首先，收集结果列表中，符合 PROGRAM-FUZZER 的所有数据，储存在 dfs 列表中
            dfs = []
            for result in results:
                fuzz_result = result.get()
                if fuzz_result[0] != FUZZER or fuzz_result[2] != PROGRAM:
                    continue
                dfs.append(fuzz_result[4])
            # 验证 REPEAT 是否和 dfs 收集到的数量一致
            assert(len(dfs) == REPEAT)
            # 每个 df 都是一个 PROGRAM-FUZZER-TIME 的 plot_data，可以绘制成一条线
            # 我们要对这些 df 的值取平均
            # slot_list 就是用来存放绘图数据数组的列表
            slot_list = []
            for df in dfs:
                # 用来绘图的数据数组
                slot = [0] * SPLIT_NUM
                # 因为是 draw_execs 先给 df 按照执行次数排序
                df = df.sort_values("total_execs")
                # 遍历排序后的数据
                for _, row in df.iterrows():
                    # 取得这一行的执行次数
                    execs = int(row["total_execs"])
                    # 根据 execs_unit 计算下标，向上取整
                    k = math.ceil(execs / execs_unit)
                    # 部分 plot_data 可能含有远超于 SPLIT_NUM 的数据，它们不会被
                    # 绘制进图片了，抛弃掉
                    if k < SPLIT_NUM:
                        slot[k] = int(row[colname])
                # 因为我们计算 k 是向上取整，所以元素0必须为0
                assert(slot[0] == 0)
                # 如果这个属性是 “积累属性”，那么就需要填补 slot 中为 0 的部分
                if accumulate:
                    for i in range(SPLIT_NUM):
                        if i > 0 and slot[i] == 0:
                            slot[i] = slot[i-1]
                slot_list.append(slot)
            # 验证，slot_list 的长度必须等于 REPEAT
            assert(len(slot_list) == REPEAT)
            # 求平均，向上取整 (向上取整的原因：如果 REPEAT=5，有一个实验找到了1个 bug，
            # 剩下4个都没找到，我们希望最后平均出来的 bug 是1而不是0)
            slot_avg = [0] * SPLIT_NUM
            for i in range(SPLIT_NUM):
                for k in range(REPEAT):
                    slot_avg[i] += slot_list[k][i]
                slot_avg[i] /= REPEAT
                slot_avg[i] = math.ceil(slot_avg[i])

            # 有了 slot_avg 就能绘图了
            # 开始绘图
            # x 轴表示执行次数
            x = [ i*execs_unit for i in range(SPLIT_NUM) ]
            y = slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 这个 PROPGRAM 绘制完毕后，要命名
        # 设置标题
        plt.title(PROGRAM + " " + name + '-execs graph')
        # 设置 x 轴
        plt.xlabel('# execs')
        # 设置 y 轴
        plt.ylabel('# ' + name)
        # 设置文件名和文件类型 (png, svg, pdf ....)
        plt.savefig(name + '_execs_' + PROGRAM + SPECIFIC_SUFFIX + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'
        # 打印日志标识成功绘制这个图片
        print("finish drawing " + name + "_execs_" + PROGRAM + SPECIFIC_SUFFIX + ".svg")
        sys.stdout.flush()
        # 关闭图形，节约内存
        plt.close() 

    # 打印日志：成功绘制完某一类型的图片
    print("============================= finish drawing " + name + "_execs graph part =============================")
    sys.stdout.flush()

############################################### 5. 绘制 crash_time   ##################################################
if draw_configure["crash_time"]:
    draw_time("crash", "saved_crashes", True)

############################################### 6. 绘制 crash_execs  ##################################################
if draw_configure["crash_execs"]:
    draw_execs("crash", "saved_crashes", True)

############################################### 7. 绘制 seed_time    ##################################################
if draw_configure["seed_time"]:
    draw_time("seed", "corpus_count", True)

############################################### 8. 绘制 seed_execs   ##################################################
if draw_configure["seed_execs"]:
    draw_execs("seed", "corpus_count", True)

############################################### 9. 绘制 Throughput  ##################################################
if draw_configure["throughput_time"]:
    draw_time("execs_per_sec", "execs_per_sec", False)

############################################### 10. 要结束了             ##################################################
# 关闭并行任务池子、退出
pool.close()
pool.join()
exit(0)  
















############################################### 2. 一些跟收集 bug triggered times 强相关的函数定义 (尽量别修改) ##############################

# 在 timeout 限制下来运行一个命令，这个函数通常用来查看一个 crash 触发了哪些 bug
def sub_run(cmd, timeout):
    try: 
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return r
    except subprocess.TimeoutExpired:
        print("time out")
        sys.stdout.flush()
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
bug_program_args = {
        # lAVAM
        "base64": "-d",        
        "md5sum": "-c",        
        "uniq": "",        
        "who": "",        
        # # MAGMA
        # "libpng_read_fuzzer": "",        
        # "sndfile_fuzzer": "",
        # "tiff_read_rgba_fuzzer": "",
        # "tiffcp": "-M",
        # "libxml2_xml_read_memory_fuzzer": "",
        # "xmllint": "--valid --oldxml10 --push --memory"
}

# afl-showmap -o mapfile -m none -e -- ./base64_PUT -d output_dir/default/queue/id:000001,src:000000,time:32,execs:84,op:colorization,pos:0,+cov
base_command = ['singularity', 'run', 'afl-showmap.sif', '/magma/fuzzers/aflplusplus/repo/afl-showmap', '-o', 'mapfile', '-m', 'none', '-e', '--', 'PUT']

# 转化时间为正确单位的函数
def convert_Time(original_time):
    # CHANGE: 正确地转化时间
    # 先转为秒
    original_time /= 1000
    # 再转为分
    original_time /= 60
    # 再转为小时
    original_time /= 60
    # 向下取整
    original_time = int(original_time)
    return original_time

# 用来记录已经完成的数据收集任务的数量
finished_tasks = multiprocessing.Value('i', 0)  # 'i' 表示整数

"""用来收集 lavam bug_time 数据的工作函数"""
def lavam_bug_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    bug_time_slot = [0] * SPLIT_NUM
    bug_time_dict = {}
    crashdir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/crashes/"
    queuedir = FUZZER + "/" + TARGET + "/" + thePROGRAM + "/" + TIME + "/findings/default/queue/"
    # 无论何时，PUT 都是同一个
    put = "aflplusplus" + "/" + TARGET + "/" + thePROGRAM + "/0/afl/" + thePROGRAM

    # 先获取 crashes 里的 bugs
    files = getfiles(crashdir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(crash_files) = " + str(len(files)))
    sys.stdout.flush()

    for crash_file in files:
        matches = re.findall(r"time:(\d+)", crash_file)
        assert(len(matches) < 2)
        if matches:
            # NOTE: 时间转换
            crash_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if crash_time < SPLIT_NUM:
                # 看看这个文件是否触发 validated_bugs
                cmd = [put]            
                assert(bug_program_args[thePROGRAM] is not None)
                if bug_program_args[thePROGRAM]:
                    cmd.append(bug_program_args[thePROGRAM])
                cmd.append(crashdir + crash_file)
                # 6 秒限制超时，运行该命令
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bug_time_dict 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        if cur_id not in bug_time_dict:                        
                            print("  Trigger %5d in: %s" % (cur_id, crash_file))
                            bug_time_dict[cur_id] = crash_time
                            bug_time_slot[crash_time] += 1

    # 再获取 seeds 里的 bugs
    files = getfiles(queuedir)
    print("PROGRAM = " + thePROGRAM + ", FUZZER = " + FUZZER + ", TIME = " + TIME + ", len(seed_files) = " + str(len(files)))
    sys.stdout.flush()

    for seed_file in files:
        matches = re.findall(r"time:(\d+)", seed_file)
        assert(len(matches) < 2)
        if matches:

            # 如果是 +pat 种子，那么跳过，因为它大概率不触发新 bugs，否则不会被列入 pat+ 池子里
            pat_matches = re.findall(r"\+pat", seed_file)
            assert(len(pat_matches) < 2)
            if pat_matches:
                continue

            # NOTE: 时间转换
            seed_time = convert_Time(int(matches[0]))

            assert(SPLIT_NUM == TOTAL_TIME)
            if seed_time < SPLIT_NUM:
                # 看看这个文件是否触发 validated_bugs
                cmd = [put]            
                assert(bug_program_args[thePROGRAM] is not None)
                if bug_program_args[thePROGRAM]:
                    cmd.append(bug_program_args[thePROGRAM])
                cmd.append(queuedir + seed_file)
                # 6 秒限制超时，运行该命令
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bug_time_dict 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        if cur_id not in bug_time_dict:                        
                            print("  Trigger %5d in: %s" % (cur_id, seed_file))
                            bug_time_dict[cur_id] = seed_time
                            bug_time_slot[seed_time] += 1
                        # 如果之前的找到的 bug 时间更晚，那么做个更新
                        if bug_time_dict[cur_id] > seed_time:                        
                            print("  early Trigger %5d in: %s" % (cur_id, seed_file))
                            bug_time_slot[bug_time_dict[cur_id]] -= 1
                            bug_time_dict[cur_id] = seed_time
                            bug_time_slot[seed_time] += 1
                
    # 先从增量数组转为存量数组
    for i in range(SPLIT_NUM-1):
        bug_time_slot[i+1] += bug_time_slot[i]

    global finished_tasks
    with finished_tasks.get_lock():
        finished_tasks.value += 1
        print(f"{finished_tasks.value} finish {FUZZER}-{TARGET}-{thePROGRAM}-{TIME} data collect")
        sys.stdout.flush()
    return (FUZZER, TARGET, thePROGRAM, TIME, bug_time_slot)

# CHANGE: 这里根据不同的数据收集任务需要改变
"""总工作函数"""
def worker(FUZZER, TARGET, thePROGRAM, TIME, task_count):
    return seed_time_worker(FUZZER, TARGET, thePROGRAM, TIME, task_count)

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

    # CHANGE 自定义 TARGETS 包含哪些
    TARGETS = ["base64"]

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
            # 开始绘图  CHANGE:
            x = [ (i+1) for i in range(SPLIT_NUM) ]
            y = result_time_slot_avg
            # 绘制图形
            plt.plot(x, y, linestyle='-', label=FUZZER) 
            # 添加图例
            plt.legend()

        # 添加标题和标签 CHANGE:
        # 注意：edges 最好使用 min 作为横轴单位！！！
        plt.title(PROGRAM + ' seed-time graph')
        plt.xlabel('time(h)')
        plt.ylabel('# seeds')
        # 保存图形为文件: 每个 PROGRAM 画一张图
        plt.savefig('seed_time_' + PROGRAM + '.svg', format='svg')  # 你可以指定文件格式，例如 'png', 'jpg', 'pdf', 'svg'

    print("total " + str(len(results)) + " fuzzing result collect tasks")
    sys.stdout.flush()

    # 要结束了
    pool.close()
    pool.join()
    exit(0)

if __name__ == '__main__':
    main()


