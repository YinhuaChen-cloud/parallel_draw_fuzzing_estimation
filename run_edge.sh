#!/bin/bash -e
#SBATCH -o job.%j.out
#SBATCH --partition=cpu
#SBATCH -J cyhDraw
#SBATCH -N 1
#SBATCH --qos=cpu
#SBATCH -c 180

python3 parallel_draw_edge.py

