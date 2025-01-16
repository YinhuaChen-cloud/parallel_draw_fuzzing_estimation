# 通过并行方法绘制 fuzzing 结果曲线图

### 绘制 Throughput

在 parallel_common.py 设置好参数，随后：
```bash
cp parallel_common.py parallel_throughput.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_throughput.py
```
会在 cache 目录下生成 throughput 的 .svg 图片
TODO: 等待测试

---

### 绘制剩余四个图之前，要做的事情

在 parallel_common.py 设置好参数，随后：
```bash
cp parallel_common.py parallel_unique.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_unique.py
```
会在 cache 目录各个 FUZZER/TARGET/PROGRAM/0/findings 下生成一个 unique 文件夹，里面包含去重后的 crashes 和 queue 文件夹
TODO: 等待测试

绘制图片后，还需要运行 xxx.py 删除掉所有的 unique 文件夹，避免下次绘图的时候产生冲突:
```bash
cp parallel_common.py parallel_delete_unique.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_delete_unique.py
```
TODO: 等待测试

---

### 绘制 seeds

TODO: here

---

### 绘制 crashes

TODO: here

---

### 绘制 edges
gg
TODO: here

---

### 绘制 bugs

TODO: here

---


一共五个文件夹，五个 .py 绘图代码

draw_normal: 绘制 crash, seed 的时间横轴图以及执行次数(execs)横轴图。同时会绘制 Throughput

draw_edge_singularity: 绘制 edge 的时间横轴图以及执行次数(execs)横轴图，收集 edges 的方式是使用 afl-showmap.sif singularity

draw_edge_docker: 绘制 edge 的时间横轴图以及执行次数(execs)横轴图，收集 edges 的方式是使用 docker 镜像

draw_bug_singularity: 绘制 bug(去重) 的时间横轴图以及执行次数(execs)横轴图。收集 bugs 的方式是使用 afl-showmap.sif singularity

draw_bug_docker: 绘制 bug(去重) 的时间横轴图以及执行次数(execs)横轴图。收集 bugs 的方式是使用 docker 镜像

具体使用方法，进入这五个文件夹，看里面的 README.md

目前可有的有：
- draw_normal
- draw_edge_singularity

