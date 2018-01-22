#!/usr/bin/env python3

# SYntax: patchobj FILE FROM TO

from sys import argv

RECORD_NAMES = ['pad', 'first', 'last', 'comment', 'dictionary', 'module', 'entry-point', 'size', 'contents', 'reference', 'computed-reference']

def short(x):
	return int.from_bytes(x[:2], byteorder='big')

def long(x):
	return int.from_bytes(x[:4], byteorder='big')

def t2s(chunk):
	try:
		chunk = chunk[0]
	except TypeError:
		pass

	return RECORD_NAMES[chunk]

def records_from_object(o):
	ctr = 0

	while ctr < len(o):
		kind = t2s(o[ctr])

		if kind in 'comment dictionary contents reference computed-reference':
			size = short(o[ctr+2:])
		elif kind == 'pad':
			size = 1
		elif kind == 'first':
			size = 4
		elif kind == 'module':
			size = 6
		elif kind == 'entry-point':
			size = 8
		elif kind == 'size':
			size = 6
		elif kind == 'last':
			size = 2

		if ctr + size > len(o):
			raise ValueError('ran past end of file')

		yield o[ctr:ctr+size]

		ctr += size

import struct

class MPWObject:
    def __init__(self):
        self._list = []
        self._dict = []
        self._backdict = {}
        self._dict_idx = 200

    def __bytes__(self):
        dest = bytearray()

        for chunk in self._list:
            dest.extend(chunk)
            if len(dest) & 1: dest.append(0)

        return bytes(dest)

    def _ensurename(self, name):
        # get the ID of this name from the dict
        # If nonexistent, then add it
        # i.e. idempotent

        try:
            return self._backdict[name]
        except KeyError:
            self.putdict([name])
            return self._backdict[name]

    def _quickappend(self, *bytelist):
        self._list.append(bytes(bytelist))

    def putfirst(self):
        self._quickappend(1, 1, 0, 2)

    def putlast(self):
        self._quickappend(2, 0)

    def putdict(self, items):
        dest = bytearray()

        dest.extend([4, 0, 99, 99])
        dest.extend(struct.pack('>H', self._dict_idx))

        flag = False

        for item in items:
            flag = True
            dest.append(len(item))
            dest.extend(item.encode('ascii'))

            self._backdict[item] = self._dict_idx

            self._dict_idx += 1 # ID of the *next* thing

        if not flag: return

        struct.pack_into('>H', dest, 2, len(dest))
        
        self._list.append(dest)

    def putmod(self, name='#0001', segname='Main', flags=(1<<7)+(1<<3)):
        modid = self._ensurename(name)
        segid = self._ensurename(segname)
        self._last_mod_id = modid

        self._list.append(struct.pack('>BBHH', 5, flags, modid, segid))

    def putentry(self, offset, name):
        entid = self._ensurename(name)

        self._list.append(struct.pack('>BBHL', 6, 1<<3, entid, offset))

    def putsize(self, size):
        self._list.append(struct.pack('>BBL', 7, 0, size))

    def putcontents(self, data): # in multiple chunks please!
        done = 0

        while done < len(data):
            this_time = data[done:done+30000]

            header = struct.pack('>BBHL', 8, 1<<3, 8 + len(this_time), done)

            self._list.append(header + this_time)

            done += len(this_time)

    def putcomment(self, cmt):
        cmt = cmt.replace('\n','\r').encode('mac_roman')
        if len(cmt) & 1: cmt += b' '

        dest = bytearray()
        dest.extend([3, 0])
        dest.extend(struct.pack('>H', len(cmt) + 4))
        dest.extend(cmt)

        self._list.append(dest)

    def putsimpleref(self, targname, width, *offsets):
        offsets = list(offsets)

        if width == 2: # of the operand field, in bytes
            flags = 1 << 4
        elif width == 4:
            flags = 0

        flags |= 1<<3 # longwords in the offset list!

        targid = self._ensurename(targname)

        dest = struct.pack('>BBHH', 9, flags, 6 + 4 * len(offsets), targid)
        dest += b''.join(struct.pack('>L', o) for o in offsets)

        self._list.append(dest)

    def putweirdref(self, targname, width, *offsets):
        # Assumes that you've already put -offset at offset
        offsets = list(offsets)

        if width == 1:
            flags = 2 << 4
        elif width == 2: # of the operand field, in bytes
            flags = 1 << 4
        elif width == 4:
            flags = 0 << 4

        flags |= 1<<7 # difference calculation
        # flags |= 1<<3 # longwords in the offset list!

        targid = self._ensurename(targname)

        dest = struct.pack('>BBHHH', 10, flags, 8 + 2 * len(offsets), targid, self._last_mod_id)
        dest += b''.join(struct.pack('>H', o) for o in offsets)

        self._list.append(dest)

def mkweirdref(targid, modid, width, *offsets):
    # Assumes that you've already put -offset at offset
    offsets = list(offsets)

    if width == 1:
        flags = 2 << 4
    elif width == 2: # of the operand field, in bytes
        flags = 1 << 4
    elif width == 4:
        flags = 0 << 4

    flags |= 1<<7 # difference calculation
    # flags |= 1<<3 # longwords in the offset list!

    dest = struct.pack('>BBHHH', 10, flags, 8 + 2 * len(offsets), targid, modid)
    dest += b''.join(struct.pack('>H', o) for o in offsets)

    return dest

def mkdict(firstid, *names):
    dest = bytearray()

    dest.extend([4, 0, 99, 99])
    dest.extend(struct.pack('>H', firstid))

    for item in names:
        dest.append(len(item))
        dest.extend(item.encode('ascii'))

    struct.pack_into('>H', dest, 2, len(dest))

    return bytes(dest)


def read_dict(d):
	this_id = int.from_bytes(d[4:6], byteorder='big')
	offset = 6

	while offset < len(d):
		slen = d[offset]
		if offset + 1 + slen > len(d):
			raise ValueError('overran dict!')

		yield this_id, d[offset+1:][:slen].decode('ascii')

		this_id += 1
		offset += 1 + slen


def read_dict_from(records):
	for r in records:
		if t2s(r) == 'dictionary':
			yield from read_dict(r)


path, path2, module, target = argv[1:]

with open(path, 'rb') as f:
	d = f.read()



olist = list(records_from_object(d))

n2s = dict(read_dict_from(olist))
s2n = {v: k for (k, v) in n2s.items()}

mod_id = s2n[module]
targ_id = max(n2s) + 1

this_is_the_module = False

ever_found_module = False
did_insert_branch = False


nulist = []


for rec in olist:
	post = []

	if t2s(rec) == 'first':
		post.append(mkdict(targ_id, target))
		if len(post[-1]) % 2:
			post.append(b'\x00')

	elif t2s(rec) == 'module':
		this_is_the_module = int.from_bytes(rec[2:4], byteorder='big') == mod_id
		if this_is_the_module: ever_found_module = True

	elif t2s(rec) == 'contents' and this_is_the_module:
		flags = rec[1]

		if not flags & (1 << 4):
			boff = 4
			if flags & (1 << 3):
				boff += 4

			if boff == 4 or not any(rec[4:8]):
				rec = bytearray(rec)
				rec[boff:boff+6] = b'\x60\xff\xff\xff\xff\xfe'
				rec = bytes(rec)

				post.append(mkweirdref(targ_id, mod_id, 4, 2))

				did_insert_branch = True

	nulist.append(rec)
	nulist.extend(post)

if not ever_found_module:
	print('WARNING: did not find module %s' % module)

if ever_found_module and not did_insert_branch:
	print('WARNING: found module but could not insert BRA.L to %s' % target)

with open(path2, 'wb') as f:
	for x in nulist:
		f.write(x)





