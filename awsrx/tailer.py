#! /usr/bin/python2.7
#coding=cp850
#mcit@geus.dk
#
#tail the in_files by lines and write them in out_subdir prepending the aws name
#
#TODO: quick hack: clean it up

import glob, sys, os, os.path
from collections import deque

def tailer(in_files, lines_limit, out_subdir='.'):
    
    for path_name, aws_info in in_files.items():
        
        aws_name, headers = aws_info
        print 'tailing', aws_name, path_name
        
        with open(path_name) as in_f:
            tail = deque(in_f, lines_limit)
        
        headers_lines = [l + '\n' for l in headers.split('\n')]
        tail = list(set(headers_lines + list(tail)))
        
        tail.sort()
        
        in_dirn, in_fn = os.path.split(path_name)    
        out_fn = '_'.join((aws_name, in_fn))
        out_pn = os.sep.join((in_dirn, out_subdir, out_fn))
        
        with open(out_pn, 'w') as out_f:
            #out_f.write(headers)
            out_f.writelines(tail)
            

