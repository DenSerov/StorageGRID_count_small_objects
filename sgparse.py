#!/usr/bin/env python3
#  for i in {2..16}; do aws --no-verify-ssl --endpoint-url $ENDPOINT \
#    s3 mb s3://demo$i --region us-east-1; done
#  for i in {1..16}; do s3tester -concurrency=8 -duration=3600 \
#    -operation=delete -endpoint=https://dc1-g1.demo.netapp.com:10443 \
#    -region=us-east-1 -bucket=demo$i -profile="default"& done

from __future__ import absolute_import
import os, sys, re, zlib, time
from platform import system
from io import open
buckets=dict()

if system()=='Windows':
    LOGPATH="C:/tmp"
    TMP="C:/tmp"
elif system()=='Linux':
    TMP=u"/tmp/sgparse"
    LOGPATH=u"/var/local/audit/export"
    TMP=LOGPATH
else:
    print('Unknown system type')

def tstamp():
    ts = time.localtime()
    return '['+time.strftime("%Y-%m-%d %H:%M:%S", ts)+'] '

def parselog (fname,buffer=100):
    global buckets
    reCSIZ=re.compile(u'\[CSIZ\(UI64\):.*?\]')
    reS3BK=re.compile(u'\[S3BK\(CSTR\):.*?\]')
    reS3KY=re.compile(u'\[S3KY\(CSTR\):.*?\]')
    count=0
    try: 
        f=open(fname,u'r',encoding='utf-8')
        print(tstamp(),fname,'was opened successfully.',file=flog)
    except OSError: 
        print(tstamp(),'WARNING: Could not open a file:', fname,file=flog)
    print('.',end='')
    lines=f.readlines(buffer)

    while lines:
        for line in lines:
          count+=1
          sput,s3ky,sdel=False, False, False
          if (u'SPUT' in line): sput=True
          if (u'S3KY' in line): s3ky=True
          if (u'SDEL' in line): sdel=True
          if s3ky & (sput | sdel):
            csiz= reCSIZ.search(line).group()[12:-1]
            buc=  reS3BK.search(line).group()[13:-2]
            s3k=  reS3KY.search(line).group()[13:-2]
            if buc not in buckets.keys():
                buckets[buc]={}
            if sput:
                buckets[buc][s3k]=csiz
            if sdel:
                try: del buckets[buc][s3k]
                except KeyError: print(tstamp(),'WARNING: Can not delete object record',s3k,'in bucket',buc,file=flog)

        try: lines=f.readlines(buffer)
        except IOError: print(tstamp(),'ERROR: failed reading buffer:',count//buffer,file=flog)
        if count%100000==0: print('.',end='')# print(count, 'lines processed')
    print()
    return

def zlib_gunzip(fgz,wbits=16+zlib.MAX_WBITS,CHUNKSIZE=2*1024*1024):
    print(tstamp(),'Decompression',fgz,'is in progress...',file=flog)
    # print(fgz,end=' ')
    progress=0
    words=fgz.split('/')
    ftxt=TMP+"/"+words[-1][:-3]
    d = zlib.decompressobj(wbits)
    fin=open(fgz,u'rb')
    fout=open(ftxt,u'wb')
    buffer=fin.read(CHUNKSIZE)
    while buffer:
        progress+=1
        outstr = d.decompress(buffer)
        fout.write(outstr)
        buffer=fin.read(CHUNKSIZE)
        if progress%10==0: print('.',end='')
    outstr = d.flush()
    fout.write(outstr)
    fout.close()
    fin.close()
    print(tstamp(),'Decompression',fgz,'is complete!',file=flog)
    return ftxt

def getlocal(logs):
    start=time.time()
    for logname in logs:
        print(tstamp(),u'Processing ',logname,file=flog)
        print(logname,end=' ')
        logname=LOGPATH+u"/"+logname
        if logname.endswith(u'gz'):
            uncompressed=zlib_gunzip(logname)
            parselog(uncompressed)
            os.remove(uncompressed)
        elif logname.endswith(u'log') or logname.endswith(u'txt') :
            parselog(logname)
        print(tstamp(),logname,'was processed in ',round(time.time()-start),'seconds.',file=flog)


def print_report(buckets):
    print('\n\nSummary')
    small_total=0
    big_total=0
    max_buc_name=0
    for buc in buckets.keys():
        len_buc_name=len(buc)
        if len_buc_name>max_buc_name: max_buc_name=len_buc_name
    print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
    print('Bucket name',' '*(max_buc_name-10),'Small objects   Big objects   Total objects ')
    for buc in buckets.keys():
        small=0
        big=0
        for obj in buckets[buc]:
            if int(buckets[buc][obj])<=131072: small+=1
            else: big+=1
        print(buc,'.'*(max_buc_name-len(buc)+2),sep='', end=' ')
        print('{0:13} {1:13d} {2:15d}'.format(small,big,small+big))
        small_total+=small
        big_total+=big
    print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
    print(' '*(max_buc_name+13),'Small objects :{0:17d}'.format(small_total))
    print(' '*(max_buc_name+13),'Big objects   :{0:17d}'.format(big_total))
    print(' '*(max_buc_name+13),'Total objects :{0:17d}'.format(small_total+big_total))
    print('_'*len('Bucket name'+ ' '*(max_buc_name-10)+' Small objects   Big objects   Total objects '))
    print('\n\nJob Finished',file=flog)
    return


################################################################
#                MAIN BODY                                     #
################################################################
def main(flog):
    try: os.mkdir(TMP)
    except OSError: print(tstamp(),u'Temporary directory exists.',file=flog)

    if os.path.exists(LOGPATH):
        print(tstamp(),u"Trying to scan local audit logs",file=flog)
        filelist=os.listdir(LOGPATH)
        logs=[]
        for fn in filelist:
            if (fn.endswith(u'.gz') or fn.endswith(u'.txt')) and (fn.startswith(u'20')):
                logs.append(fn)
        logs.append('audit.log')
        logs.sort()
        print(tstamp(),logs,file=flog)
        getlocal(logs)
        print_report(buckets)
    else:
        print(tstamp(),u"\nERROR: Directory", LOGPATH, u"is not found on this host.\n\n",file=flog)
        print(tstamp(),u"Check if you are launching this script on correct host, or specify remote hostname to run remote scan.\n\n",file=flog)
        print(tstamp(),u"Usage for remote scan                : bash ",sys.argv[0],u" [remote_hostname]\n",file=flog)
        print(tstamp(),u"Usage for local scan on SG Admin Node: bash ",sys.argv[0],u"\n\n",file=flog)

if __name__=='__main__':
    flog=open('sgparse.log','a')
    main(flog)
    flog.close()
