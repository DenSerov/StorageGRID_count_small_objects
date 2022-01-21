#!/usr/bin/env python3
#  for i in {2..16}; do aws --no-verify-ssl --endpoint-url $ENDPOINT \
#    s3 mb s3://demo$i --region us-east-1; done
#  for i in {1..16}; do s3tester -concurrency=8 -duration=3600 \
#    -operation=delete -endpoint=https://dc1-g1.demo.netapp.com:10443 \
#    -region=us-east-1 -bucket=demo$i -profile="default"& done

#from __future__ import absolute_import
from os import listdir, path, mkdir
from re import compile
from sys import getsizeof
from zlib import decompressobj, MAX_WBITS
from time import time, localtime, strftime,sleep
from json import loads, dumps
from multiprocessing import Process, Pipe

LOGPATH="/var/local/audit/export"
TMP="."

def tstamp():
    ts = localtime()
    return '['+strftime("%Y-%m-%d %H:%M:%S", ts)+'] '

def parselogProc (pipe):
    def print_report(buckets):  
        small_total=0
        big_total=0
        max_buc_name=0
        print('\n\nSummary')
        for buc in buckets.keys():
            len_buc_name=len(buc)
            if len_buc_name>max_buc_name: max_buc_name=len_buc_name
        print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
        print('Bucket name',' '*(max_buc_name-10),'Small objects   Big objects   Total objects ')
        for buc in buckets.keys():
            small=0
            big=0
            for s3k in buckets[buc]["objects"]:
                if int(buckets[buc]["objects"][s3k])<1: small+=1
                else: big+=1
            print(buc,'.'*(max_buc_name-len(buc)+2),sep='', end=' ')
            print('{0:13,d} {1:13,d} {2:15,d}'.format(small,big,small+big))
            small_total+=small
            big_total+=big
        print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
        print(' '*(max_buc_name+13),'Small objects :{0:17,d}'.format(small_total))
        print(' '*(max_buc_name+13),'Big objects   :{0:17,d}'.format(big_total))
        print(' '*(max_buc_name+13),'Total objects :{0:17,d}'.format(small_total+big_total))
        print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
        return
        
    start=time()
    print('ParselogProc started...')
    buckets={}
    parselog=open(TMP+'/parse.log','a')
    reCSIZ=compile(u'\[CSIZ\(UI64\):.*?\]')
    reS3BK=compile(u'\[S3BK\(CSTR\):.*?\]')
    reS3KY=compile(u'\[S3KY\(CSTR\):.*?\]')
    count=0
    last_elapsed=0
    ## Read from the pipe; this will be spawned as a separate Process
    p_output, p_input = pipe
    p_input.close()    # We are only reading

    while True:
        msg = p_output.recv()
        if msg == 'DONE': break
        lines = msg.splitlines()
        for line in lines:
            count+=1
            #print(count,line)
            sput,s3ky,sdel=False, False, False
            if (u'SPUT' in line): sput=True
            if (u'S3KY' in line): s3ky=True
            if (u'SDEL' in line): sdel=True
            if s3ky & (sput | sdel):
                csiz= int(reCSIZ.search(line).group()[12:-1]) // 131072
                buc=  reS3BK.search(line).group()[13:-2]
                s3k=  hash(reS3KY.search(line).group()[13:-2]) % (10**8)
                if buc not in buckets.keys():
                    buckets[buc]={"bucname":buc}
                    buckets[buc]["objects"]={}
                if sput:
                    buckets[buc]["objects"][s3k]=csiz
                if sdel:
                    try: del buckets[buc]["objects"][s3k]
                    except KeyError: print(tstamp(),'WARNING: Can not delete object record in bucket',buc,file=parselog)
            if count % (10**5) == 0: 
                elapsed=time()-start
                print('.',end='') # print(count, 'lines processed')
                if count % (10**6) == 0: #print('{0:,d} lines processed.'.format(count))
                    run10mln = elapsed - last_elapsed
                    last_elapsed=elapsed
                    pos=msg[0:19]
                    print("""\n{0:,d}M lines processed. Current pos {1:}. Only {2:5.2f} sec elapsed from start. Last 1M Avg {3:,d} lines/sec. Overall Avg {4:,d} lines/sec. Since last 1M point: {5:2.2f} sec."""\
                        .format(count // (10**6) ,pos,round(elapsed,2),int(round(10**6)/run10mln),int(round(count/elapsed)),round(run10mln,2)))
                if count % (10**7) == 0: 
                    print('\nPreliminairy Report at',pos)
                    print_report(buckets)
    print('Final Report')
    print_report(buckets)


def zlib_gunzip_to_pipe(p_input,fgz,wbits=16+MAX_WBITS,CHUNKSIZE=2*1024*1024):
    d = decompressobj(wbits)
    b=0
    fin=open(fgz,u'rb')
    tail=b''
    firstCRpos = 0
    buffer=fin.read(CHUNKSIZE)                      # Read 1st buffer from compressed file
    while buffer:       
        b+=1
        tmpstr = d.decompress(buffer)               # Decompress buffer contents
        firstCRpos = 0                              # Reset head position counter
        head = b''                                  # Reset head content
        lastCRpos = tmpstr.rfind(b'\n')             # Last occurence of \n symbol (to cut the tail)
        if len(tail)>1:                             # If previous decompressed text had split record tail
            firstCRpos = tmpstr.find(b'\n')         # First occurence of \n symbol is (to cut the head)
            head=tail[1:] + tmpstr[:firstCRpos]     # previous tail + new head
        payload = head + tmpstr[firstCRpos:lastCRpos] # Clean payload without split records
        tail = tmpstr[lastCRpos:]                   # cut tail of the last decompressed text for joining with following head
        p_input.send(payload.decode(errors="ignore"))# Send clean records for processing
        buffer=fin.read(CHUNKSIZE)                  # Get new buffer for decompression
    print('{0} buffers read.'.format(b))
    payload = d.flush()                             # Get what remained
    p_input.send(payload.decode(errors="ignore"))   # Send remaining text for processing
    fin.close()

def send_to_pipe(p_input,fname):
    f = open(fname,'r',encoding='utf-8',errors='ignore')
    buffer=10**6
    lines = f.readlines(buffer)
    while lines:
        p_input.send("".join(lines))
        lines = f.readlines(buffer)
    f.close()
            
def getlocal(p_input, logs):
    # p_input,p_output = pipe
    # p_output.close()
    print("Processing",logs)
    for logname in logs:
        start=time()
        print(logname,'decompressing')
        logname=LOGPATH+u"/"+logname
        if logname.endswith(u'gz'):
            zlib_gunzip_to_pipe(p_input, logname)
        elif logname.endswith(u'log') or logname.endswith(u'txt') :
            send_to_pipe(p_input, logname)
        fsiz=path.getsize(logname)/1024/1024
        elapsed=time()-start
        print(tstamp(),logname,'was processed in ',elapsed,'seconds. Average speed was ',round(fsiz/elapsed,1),'MB/sec')
    p_input.send('DONE')

# def print_report(buckets):  
#     from gc import collect as garbage_collector
#     small_total=0
#     big_total=0
#     max_buc_name=0

#     del buckets
#     garbage_collector()
#     fp=open(TMP+'/buckets.json', 'rt')

#     print('\n\nSummary')
#     for buc in buckets.keys():
#         len_buc_name=len(buc)
#         if len_buc_name>max_buc_name: max_buc_name=len_buc_name
#     print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
#     print('Bucket name',' '*(max_buc_name-10),'Small objects   Big objects   Total objects ')
#     for buc in buckets.keys():
#         small=0
#         big=0
#         for obj in buckets[buc]:
#             if int(buckets[buc][obj])<=131072: small+=1
#             else: big+=1
#         print(buc,'.'*(max_buc_name-len(buc)+2),sep='', end=' ')
#         print('{0:13,d} {1:13,d} {2:15,d}'.format(small,big,small+big))
#         small_total+=small
#         big_total+=big
#     print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
#     print(' '*(max_buc_name+13),'Small objects :{0:17,d}'.format(small_total))
#     print(' '*(max_buc_name+13),'Big objects   :{0:17,d}'.format(big_total))
#     print(' '*(max_buc_name+13),'Total objects :{0:17,d}'.format(small_total+big_total))
#     print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
#     return




################################################################
#                MAIN BODY                                     #
################################################################
def main():
    # Pipes are unidirectional with two endpoints:  p_input ------> p_output
    p_output, p_input = Pipe()  # writer() writes to p_input from _this_ process
    reader_p = Process(target=parselogProc, args=((p_output, p_input),))
    reader_p.daemon = True
    reader_p.start()     # Launch the reader process
    # p_output.close()

    print(tstamp(),u"Trying to scan local audit logs")
    filelist=listdir(LOGPATH)
    logs=[]
    for fn in filelist:
        if (fn.endswith(u'.gz') or fn.endswith(u'.txt')) and (fn.startswith(u'20')):
            logs.append(fn)
    if path.isfile(LOGPATH+'/audit.log'): logs.append('audit.log')
    logs.sort()
    print(tstamp(),logs)
    getlocal(p_input, logs)
    reader_p.join()
    p_input.close()

if __name__=='__main__':
    if path.exists(LOGPATH):
        start=time()
        if not path.exists(TMP): mkdir(TMP)
        main()
        print('It took only {0:,} seconds to process.'.format(round(time()-start,0)))
    else:
        print(LOGPATH,'does not exist. Program abbort.')