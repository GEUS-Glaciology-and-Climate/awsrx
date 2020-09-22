#! /usr/bin/python2.7
#coding=cp850
#mcit@geus.dk
#
#sort the lines in all files passed on the command line (can drag and drop)

import glob, sys, os, os.path

def sorter(modified_files, replace_unsorted=True):
    
    for pn, aws_info in modified_files.items():
        
        aws_name, headers = aws_info
        
        print 'sorting', pn
        
        with open(pn) as in_f:
            lines = in_f.readlines()
        
        headers_lines = [l + '\n' for l in headers.split('\n')]
        unique_lines = list(set(headers_lines + lines))
        duplicates_count = len(lines) - len(unique_lines)
        if duplicates_count:
            print '  %i duplicates' %duplicates_count
        
        unique_lines.sort()
        
        in_dirn, in_fn = os.path.split(pn)    
        out_fn = 'sorted_' + in_fn
        out_pn = os.sep.join((in_dirn, out_fn))
        
        with open(out_pn, 'w') as out_f:
            #out_f.write(headers)
            out_f.writelines(unique_lines)
            
        if replace_unsorted:
            os.remove(pn)
            os.rename(out_pn, pn)


if __name__ == '__main__':
    
    in_pathnames = sys.argv[1:]
    
    sys.exit(sorter(in_pathnames))
