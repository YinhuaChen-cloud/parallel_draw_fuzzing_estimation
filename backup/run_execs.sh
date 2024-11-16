#!/bin/bash -e
#SBATCH -o job.%j.out
#SBATCH --partition=a100
#SBATCH -J cyhFuzz
#SBATCH -N 1
#SBATCH --qos=a100
#SBATCH -c 90

python3 parallel_draw_execs.py

