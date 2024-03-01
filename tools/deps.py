#!/usr/bin/env python3

import os.path
import glob
import argparse
import re
import itertools

def read_lines(path, limit):
	with open(path, 'r') as f:
		for line in f:
			if limit == 0:
				break
			limit -= 1
			yield line

def include_lines(path):
	return [line for line in read_lines(path, 100) if line.startswith("#include <silkworm/")]

def parse_include_line_path(line):
	return re.search('<([^>]+)>', line).group(1)

def include_paths(path):
	return [parse_include_line_path(line) for line in include_lines(path)]

def module_of_path(path):
	return os.path.dirname(path)[len("silkworm/"):]

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('module', help='for example: node/snapshots')
	return parser.parse_args()

def sources_list(src_dir):
	return glob.glob(os.path.join(src_dir, os.path.join("**", "*.?pp")), recursive=True)

def include_modules(src_dir, module):
	sources = sources_list(src_dir)
	module_sources = [s for s in sources if module in s]
	module_include_paths = itertools.chain(*[include_paths(s) for s in module_sources])
	return sorted(set([module_of_path(p) for p in module_include_paths]))

script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.join(script_dir, os.path.join("..", ".."))
src_dir = os.path.join(project_dir, "silkworm")
args = parse_args()

module = args.module
print(module, "module depends on:")
num = 0
for m in include_modules(src_dir, module):
	num += 1
	print("{:2}. {}".format(num, m))
