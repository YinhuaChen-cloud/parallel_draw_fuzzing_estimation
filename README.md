# 通过并行方法绘制 fuzzing 结果曲线图

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
TODO: 等待测试

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

### 绘制 edges

<!-- 为了绘制 edges 图，需要 afl-showmap，这里先 docker pull 一个带有 afl-showmap 的 docker images
```bash
docker pull chenyinhua/afl-showmap-image:latest
```

可以用以下方法运行镜像中的 afl-showmap
```bash
docker run chenyinhua/afl-showmap-image /magma/fuzzers/aflplusplus/repo/afl-showmap
``` -->
若没有 singularity，把非 +pat 种子打包给我，我来画吧，或者把非 +pat 种子传输到其它有 sudo 权限的机器上

TODO: 等待测试

---

### 绘制 bugs

parallel_bug.py
TODO: 写代码中

---




