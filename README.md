# 通过并行方法绘制 fuzzing 结果曲线图

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




