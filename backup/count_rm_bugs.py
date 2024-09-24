#!/usr/bin/env python3
# coding=utf-8
# python >= 3.5
# From https://github.com/AngoraFuzzer/Angora/blob/master/tools/lava_validation.py
"""
python3 lava_validation.py path-to-output-dir path-to-validated_bugs-file path-to-program [args..]
e.g.
python3 lava_validation.py ./output/ ./path-to-lava-M/who/validated_bugs ./who 
python3 lava_validation.py ./output/ ./path-to-lava-M/md5sum/validated_bugs ./md5sum -c

"""
import sys                                                                             
import os     
import subprocess        
import time                 
import shutil

# 把 pstr 添加到 path 这个文件的末尾
def append_file(pstr, path):                    
    f = open(path, 'a')                           
    f.write("%s\n" % pstr)
    f.close()
    return               

# 在 timeout 限制下来运行一个命令
def sub_run(cmd, timeout):
    try: 
         r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
         return r
    except subprocess.TimeoutExpired:
        print("time out")
        return None
    return None
                                     
def locate_crashes(crash_dirs, prom_bin, flags, save_dir, bugs_id={}):
    for cur_dir in crash_dirs:
        is_crash_dir = cur_dir.endswith("crashes/")
        for file in os.listdir(cur_dir):
            if (file != "README.txt"):                
                cur_file = cur_dir + file
                cmd = [prom_bin]            
                for flag in flags:
                    cmd.append(flag)
                cmd.append(cur_file)
                cmd = ["timeout", "-s", "KILL", "--preserve-status", "4"] + cmd
                r = sub_run(cmd, 6)
                # 如果没有输出，下一个文件
                if r is None:
                    continue
                # 如果有输出，那么检查是否 trigger 了注入的 bugs
                out = r.stdout.split(b'\n')
                has_crash_id = False      
                for line in out:
                    # 如果 trigger 了 bugs，那么存入 bugs_id 字典，同时做些处理
                    if line.startswith(b"Successfully triggered bug"):
                        dot = line.split(b',')[0]
                        cur_id = int(dot[27:])
                        has_crash_id = True
                        if cur_id not in bugs_id:                        
                            print("  Trigger %5d in: %s" % (cur_id, cur_file))
                            if is_crash_dir:
                                sub_run(["mv", cur_file, save_dir + "bug-" + str(cur_id)], 3)
                            else:
                                sub_run(["cp", cur_file, save_dir + "bug-" + str(cur_id)], 3)
                            bugs_id[cur_id] = 1
                        else:
                            bugs_id[cur_id] += 1       
                            if is_crash_dir:
                                sub_run(["rm", cur_file], 3)
                if has_crash_id == False and is_crash_dir:
                    print("  NO Trigger       for: %s" % cur_file)
    return bugs_id

if __name__ == "__main__":
    flags = []                                              
    fuzzer = ""                                                               
    prom = ""                                               
    output_dir = ""
    val_file = ""
    # 至少需要 4 个参数
    if len(sys.argv) > 3:
        # 第一个参数是 output_dir (到 default 这一层深度)
        output_dir = sys.argv[1]
        # 第二个参数是 LAVAM 的 validated_bugs
        val_file = sys.argv[2]
        # 第三个参数是 PROGRAM
        prom = sys.argv[3]
    else:
        print("The command format is : dir(e.g. output) validated_file(lava provide) prom(e.g. base64) {flags(-d)}")
        exit()
    # 剩余的参数就是 PROGRAM 的参数
    if len(sys.argv) > 4:
        flags = sys.argv[4:]

    print("Target progrom is : ", prom, flags)

    # val_ids 是从 validated_bugs 中读取出来的 BUG ID 号
    val_ids = []
    extra_ids = []
    with open(val_file, 'r') as f:
        d = f.read()
        val_ids = list(map(int, d.split()))
        sorted(val_ids)

    # 创建 bugs 文件夹
    unique_dir = output_dir + "/bugs/"
    if not os.path.isdir(unique_dir):
        os.mkdir(unique_dir)

    # crash_dirs 包括 crashes 目录和 queue 目录
    crash_dirs = [output_dir + "/crashes/", output_dir + "/queue/"]
    log_file = output_dir + "/bug_log.txt"
    cnt_file = output_dir + "/bug_cnt.txt"
    bugs_id = {}

    # 开始时间
    t0 = int(time.time())

    while True:
        # 距离启动脚本的时间
        t = int(time.time()) - t0
        print("Collecting bugs at %d" % t)

        bugs_id = locate_crashes(crash_dirs, prom, flags, unique_dir, bugs_id)

        id_lists = list(bugs_id.keys())

        id_lists.sort()
        for i in id_lists:
            if i not in val_ids and i not in extra_ids:
                extra_ids.append(i)

        append_file("-" * 80, log_file)
        append_file("Found ids: " + " ".join(str(i) for i in id_lists), log_file)
        append_file("Number of found ids: " + str(len(bugs_id)), log_file)
        append_file("Extra ids: " + " ".join(str(i) for i in extra_ids), log_file)
        fail_ids = list(set(val_ids) - set(id_lists))
        append_file("Fail ids: " + " ".join(str(i) for i in fail_ids), log_file)
        cnt = len(id_lists)
        append_file("%d,%d" % (t, cnt), cnt_file)

        # 每 15 秒运行一次
        :wa
        time.sleep(15)
