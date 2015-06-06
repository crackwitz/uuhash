#!/usr/bin/env python

import os
import hashlib
import binascii
import struct

__all__ = ["UUHash"]

# https://en.wikipedia.org/wiki/UUHash

# MLDonkey source code, file src/utils/lib/fst_hash.c, retrieved 2014-08-20
# http://sourceforge.net/projects/mldonkey/files/mldonkey/3.1.5/mldonkey-3.1.5.tar.bz2

# http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/libkern/crc32.c

def UUHash(fobj):
	chunksize = 307200
	
	fobj.seek(0, os.SEEK_END)
	filesize = fobj.tell()

	fobj.seek(0)
	chunk = fobj.read(chunksize)
	md5hash = hashlib.md5(chunk).digest()

	smallhash = 0
	
	if filesize > chunksize:
		lastpos = fobj.tell()
		offset = 0x100000
		
		while offset + 2*chunksize < filesize: # yes, LESS than, not equal
			fobj.seek(offset)
			chunk = fobj.read(chunksize)
			
			smallhash = binascii.crc32(chunk, smallhash)
			
			lastpos = offset + chunksize
			offset <<= 1
		
		endlen = filesize - lastpos
		if endlen > chunksize:
			endlen = chunksize
		
		fobj.seek(filesize-endlen)
		chunk = fobj.read(endlen)
		smallhash = binascii.crc32(chunk, smallhash)

	smallhash = ((~smallhash) ^ filesize) % 2**32
	
	return md5hash + struct.pack("<I", smallhash)

if __name__ == '__main__':
	import sys
	import glob
	import base64
	import time

	files = []

	for globbable in sys.argv[1:]:
		files += glob.glob(globbable) or [globbable]

	for fname in files:
		if not os.path.isfile(fname): continue
		t0 = time.time()
		hash = UUHash(file(fname, 'rb'))
		t1 = time.time()
		encoded = base64.b64encode(hash)
		print "%-28s" % encoded, hash.encode('hex').upper(), fname
