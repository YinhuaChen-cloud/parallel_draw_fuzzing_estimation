# 通过并行方法绘制 fuzzing 结果曲线图

运行下面的绘图程序之前需要先在 parallel_common.py 的 "0.配置部分" 做出相应的修改

### 绘制 Throughput

在 parallel_common.py 设置好参数，随后：
```bash
cp parallel_common.py parallel_throughput.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_throughput.py
```
会在 cache 目录下生成 throughput 的 .svg 图片
NOTE: 已经通过测试

---

### 绘制剩余四个图之前，要做的事情

在 parallel_common.py 设置好参数，随后：
```bash
cp parallel_common.py parallel_unique.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_unique.py
```
会在 cache 目录各个 FUZZER/TARGET/PROGRAM/0/findings 下生成一个 unique 文件夹，里面包含去重后的 crashes 和 queue 文件夹
NOTE: 已经经过测试

绘制图片后，还需要运行 xxx.py 删除掉所有的 unique 文件夹，避免下次绘图的时候产生冲突:
```bash
cp parallel_common.py parallel_delete_unique.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_delete_unique.py
```
NOTE: 已经通过测试

---

### 绘制 crash 图 和 seed 图

先使用 parallel_unique.py 生成 unique 文件夹

在 parallel_common.py 设置好参数，随后：
```bash
cp parallel_common.py parallel_crash_seed.py <储存fuzzing结果的workdir>/cache 
cd <储存fuzzing结果的workdir>/cache 
python3 parallel_crash_seed.py
```
NOTE: 已经经过测试

---

### 绘制 edges 图

parallel_edge.py
NOTE: 已经通过测试

---

### 绘制 bugs 图

parallel_bug.py
NOTE: 已经通过测试

---




