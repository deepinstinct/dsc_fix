#!/usr/bin/python

'''
    File name: dsc_fix.py
    Author: Amir Amitai
    Copyright: Copyright 2017, Deep Instinct
    License: GPL-3
    Python Version: 2.7
    IDA Version: 6.95
'''

try:
    import idc
    import idaapi
    import idautils
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


import functools
import string
import struct
import re
import mmap
import collections
import os
import sys

# to get into the pymacho python module inside the external Mach-O folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR,"Mach-O"))

from pymacho.MachO import MachO
from pymacho.MachODYLDInfoCommand import MachODYLDInfoCommand
from pymacho.MachODYLinkerCommand import MachODYLinkerCommand
from pymacho.MachODYSymtabCommand import MachODYSymtabCommand
from pymacho.MachOEncryptionInfoCommand import MachOEncryptionInfoCommand
from pymacho.MachOLinkeditDataCommand import MachOLinkeditDataCommand
from pymacho.MachOLoadDYLibCommand import MachOLoadDYLibCommand
from pymacho.MachOMainCommand import MachOMainCommand
from pymacho.MachORPathCommand import MachORPathCommand
from pymacho.MachOSegment import MachOSegment
from pymacho.MachOSourceVersionCommand import MachOSourceVersionCommand
from pymacho.MachOSymtabCommand import MachOSymtabCommand
from pymacho.MachOThreadCommand import MachOThreadCommand
from pymacho.MachOUUIDCommand import MachOUUIDCommand
from pymacho.MachOVersionMinCommand import MachOVersionMinCommand
from pymacho.Constants import LC_SEGMENT,\
                                LC_SEGMENT_64,\
                                LC_DYLD_INFO_ONLY,\
                                LC_DYLD_INFO,\
                                LC_DYSYMTAB,\
                                LC_SYMTAB,\
                                LC_LOAD_DYLINKER,\
                                LC_DYLD_ENVIRONMENT,\
                                LC_UUID,\
                                LC_VERSION_MIN_MACOSX,\
                                LC_VERSION_MIN_IPHONEOS,\
                                LC_UNIXTHREAD,\
                                LC_THREAD,\
                                LC_MAIN,\
                                LC_LOAD_DYLIB,\
                                LC_LOAD_WEAK_DYLIB,\
                                LC_REEXPORT_DYLIB,\
                                LC_ID_DYLIB,\
                                LC_CODE_SIGNATURE,\
                                LC_SEGMENT_SPLIT_INFO,\
                                LC_FUNCTION_STARTS,\
                                LC_DATA_IN_CODE,\
                                LC_DYLIB_CODE_SIGN_DRS,\
                                LC_RPATH,\
                                LC_SOURCE_VERSION,\
                                LC_ENCRYPTION_INFO

# idc missing constants
SEGPERM_EXEC = 1
SEGPERM_WRITE = 2
SEGPERM_READ = 4


class FileInFile(object):
    """ This class wraps a file object and uses
    the since_offset member to anchor the beggining of it.

    Example:
    f = open("somefile.txt", "rb")
    fif = FileInFile(f, 550)
    f.seek(550)
    data1 = f.read(5)
    fif.seek(0)
    data2 = fif.read(5)
    if data2 == data1: # True
        ....
    """
    def __init__(self, fd, since_offset=0):
        self._file = fd
        self._since_offset = since_offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self._file.seek(offset + self._since_offset, whence)
            return
        elif whence == 1:
            self._file.seek(offset, whence)
            return

        raise RuntimeError("only implemented for whence in [0, 1]", offset, whence)

    def tell(self):
        ret = self._file.tell() - self._since_offset
        return ret

    def read(self, n=None):
        return self._file.read(n)

    def __getattr__(self, attr):
        return getattr(self._file, attr)


def readcstr(f, minimum=4):
    """ Reads a cstring (string +"\0") out of a stream
        f - filestream """
    ret = []
    c = f.read(1)
    while c in string.printable:
        ret.append(c)
        c = f.read(1)
    ret = "".join(ret)
    if len(ret) < minimum:
        return None
    return ret


class dsc_header(object):
    """ dyld shared cache struct taken from:
        dsc_extractor/dyld-210.2.3/launch-cache/dyld_cache_format.h"""
    def __init__(self, dsc_file):
        self._file = dsc_file
        self._parse()

    def _parse(self):
        self.magic = self._file.read(16)
        self.mapping_offset, = struct.unpack("<I", self._file.read(4))
        self.mapping_count, = struct.unpack("<I", self._file.read(4))
        self.images_offset, = struct.unpack("<I", self._file.read(4))
        self.images_count, = struct.unpack("<I", self._file.read(4))
        self.dyld_base_address, = struct.unpack("<Q", self._file.read(8))
        self.code_signature_offset, = struct.unpack("<Q", self._file.read(8))
        self.code_signature_size, = struct.unpack("<Q", self._file.read(8))
        self.slide_info_offset, = struct.unpack("<Q", self._file.read(8))
        self.slide_info_size, = struct.unpack("<Q", self._file.read(8))


class _dyld_cache_mapping_info(object):
    """ dyld shared cache struct taken from:
       dsc_extractor/dyld-210.2.3/launch-cache/dyld_cache_format.h """
    def __init__(self, dsc_file):
        self._file = dsc_file
        self._parse()

    def _parse(self):
        self.address, = struct.unpack("<Q", self._file.read(8))
        self.size, = struct.unpack("<Q", self._file.read(8))
        self.file_offset, = struct.unpack("<Q", self._file.read(8))
        self.max_prot, = struct.unpack("<I", self._file.read(4))
        self.init_prot, = struct.unpack("<I", self._file.read(4))


def dyld_cache_mapping_info(dsc_file, count):
    """ Uses _dyld_cache_mapping_info for reading an array of that struct """
    ret = []
    for i in xrange(count):
        ret.append(_dyld_cache_mapping_info(dsc_file))
    return ret


class _dyld_cache_image_info(object):
    """ dyld shared cache struct taken from:
        dsc_extractor/dyld-210.2.3/launch-cache/dyld_cache_format.h """
    def __init__(self, dsc_file):
        self._file = dsc_file
        self._parse()

    def _parse(self):
        self.address, = struct.unpack("<Q", self._file.read(8))
        self.mod_time, = struct.unpack("<Q", self._file.read(8))
        self.inode, = struct.unpack("<Q", self._file.read(8))
        self.pathfile_offset, = struct.unpack("<I", self._file.read(4))
        self.pad, = struct.unpack("<I", self._file.read(4))


def dyld_cache_image_info(dsc_file, count):
    """ uses _dyld_cache_image_info for reading an array of that struct """
    ret = []
    for i in xrange(count):
        ret.append(_dyld_cache_image_info(dsc_file))
    return ret


def mapped_address(header, cache, addr):
    cache.seek(header.mapping_offset)
    mappings = dyld_cache_mapping_info(cache, header.mapping_count)
    for m in mappings:
        if m.address <= addr and addr < (m.address + m.size):
            return m.file_offset + addr - m.address

    return None


class MachO_patched(MachO):
    """ overrides the stock load_commands method so it would fail
        gracefully without an exception and keep parsing the next commands """
    def __init__(self, macho_file, should_load_symtab=False):
        self._should_load_symtab = should_load_symtab
        super(MachO_patched, self).__init__()
        macho_file.seek(0)
        self.load_file(macho_file)

    def load_commands(self, macho_file):
        # print "[+] load_commands:"
        assert macho_file.tell() == 28 or macho_file.tell() == 32
        is_64 = self.header.is_64()
        for i in range(self.header.ncmds):
            before = macho_file.tell()
            cmd, cmdsize = struct.unpack('<II', macho_file.read(8))
            # print "[+] cmd:%d, cmdsize:%d" % (cmd, cmdsize)
            try:
                if cmd == LC_SEGMENT:
                    self.segments.append(MachOSegment(macho_file))
                elif cmd == LC_SEGMENT_64:
                    self.segments.append(MachOSegment(macho_file, arch=64))
                elif cmd in [LC_DYLD_INFO_ONLY,
                             LC_DYLD_INFO]:
                    self.commands.append(MachODYLDInfoCommand(macho_file, cmd))
                elif cmd == LC_SYMTAB and self._should_load_symtab:
                    self.commands.append(MachOSymtabCommand(macho_file._file, cmd, is_64=is_64))
                elif cmd == LC_DYSYMTAB:
                    self.commands.append(MachODYSymtabCommand(macho_file, cmd))
                elif cmd in [LC_LOAD_DYLINKER,
                             LC_DYLD_ENVIRONMENT]:
                    self.commands.append(MachODYLinkerCommand(macho_file, cmd, is_64=is_64))
                elif cmd == LC_UUID:
                    self.commands.append(MachOUUIDCommand(macho_file, cmd))
                elif cmd in [LC_VERSION_MIN_MACOSX,
                             LC_VERSION_MIN_IPHONEOS]:
                    self.commands.append(MachOVersionMinCommand(macho_file, cmd))
                elif cmd in [LC_UNIXTHREAD,
                             LC_THREAD]:
                    self.commands.append(MachOThreadCommand(macho_file, cmd))
                elif cmd == LC_MAIN:
                    self.commands.append(MachOMainCommand(macho_file, cmd))
                elif cmd in [LC_LOAD_DYLIB,
                             LC_LOAD_WEAK_DYLIB,
                             LC_REEXPORT_DYLIB,
                             LC_ID_DYLIB]:
                    self.commands.append(MachOLoadDYLibCommand(macho_file, cmd))
                elif cmd in [LC_CODE_SIGNATURE,
                             LC_SEGMENT_SPLIT_INFO,
                             LC_FUNCTION_STARTS,
                             LC_DATA_IN_CODE,
                             LC_DYLIB_CODE_SIGN_DRS]:
                    self.commands.append(MachOLinkeditDataCommand(macho_file, cmd))
                elif cmd == LC_RPATH:
                    self.commands.append(MachORPathCommand(macho_file, cmd))
                elif cmd == LC_SOURCE_VERSION:
                    self.commands.append(MachOSourceVersionCommand(macho_file, cmd))
                elif cmd == LC_ENCRYPTION_INFO:
                    self.commands.append(MachOEncryptionInfoCommand(macho_file, cmd))
                else:
                    raise RuntimeError("Unknown command", cmd)
            except KeyboardInterrupt:
                raise
            except Exception:
                macho_file.seek(before)
                macho_file.read(cmdsize)
                # print "    [!] coudln't parse load command : 0x%x - skipping %d bytes" % (cmd, cmdsize)


class DyldWalker:
    """ class the iterates images and segments a given dyld cache file """
    def __init__(self, cache, cache_symbols):
        self.cache = cache
        self._cache_symbols = cache_symbols
        self._symbols_table = {}

    def get_export_name_for_addr(self, addr):
        name_offset_in_cache = self._symbols_table.get(addr)
        if name_offset_in_cache:
            self.cache.seek(name_offset_in_cache)
            return normalize_export_name(readcstr(self.cache))

    def _cache_macho_symbols(self, m, path):
        symtab = [c for c in m.commands if c.cmd == 2]
        if not symtab:
            print "[!] no symatab for: %s" % path
            return

        symtab = symtab[0]
        for sym in symtab.syms:
            self._symbols_table[sym.n_value] = symtab.stroff + sym.n_strx

    def _walk_segments_inner(self, header, mappings, dylib_path, mac_offset, slide, callback):
        m = None
        try:
            fif = FileInFile(self.cache, mac_offset)
            m = MachO_patched(fif, should_load_symtab=self._cache_symbols)
            if self._cache_symbols:
                self._cache_macho_symbols(m, dylib_path)
        except KeyboardInterrupt:
            raise
        except Exception, e:
            raise RuntimeError("    [!] failed to MachO load",
                               e,
                               header,
                               mappings,
                               dylib_path,
                               mac_offset,
                               slide,
                               callback)
        for seg in m.segments:
            callback(fif, dylib_path, seg, slide, mac_offset)

    def walk_segments(self, callback, verbose=False):
        """ walks segments within dyld macho image
            callback - func(header, mappings, dylib_path, macho_offset, slide) """
        self.walk_images(functools.partial(self._walk_segments_inner,
                                           callback=callback),
                         verbose=verbose)

    def walk_images(self, callback, verbose=False):
        """ walks images within dyld cache
            callback - func(header, mappings, dylib_path, macho_offset, slide) """
        self.cache.seek(0)
        header = dsc_header(self.cache)
        slide = 0
        self.cache.seek(header.mapping_offset, 0)
        mappings = dyld_cache_mapping_info(self.cache, header.mapping_count)
        if header.mapping_offset >= 0x48:

            self.cache.seek(mappings[1].file_offset, 0)
            stored_ptr_to_header, = struct.unpack("<Q", self.cache.read(8))
            slide = stored_ptr_to_header - mappings[0].address

        self.cache.seek(header.images_offset)
        dylibs = dyld_cache_image_info(self.cache, header.images_count)
        i = 0
        for d in dylibs:
            i += 1
            self.cache.seek(d.pathfile_offset)
            dylib_path = readcstr(self.cache)
            mac_offset = mapped_address(header, self.cache, d.address)
            try:
                print "[+] %4d/%d 0x%08X Reading %s" % (i,
                                                        header.images_count,
                                                        mac_offset,
                                                        dylib_path)
                callback(header, mappings, dylib_path, mac_offset, slide)
            except KeyboardInterrupt:
                raise
            except Exception, e:
                if verbose:
                    print "[!] failed loading dylibPath: %s" % dylib_path
                    print e.args[1]
                raise


class AddressesIndexer:
    """ caches addresses for each macho segment """
    def __init__(self, cache, cache_symbols):
        self._addrs = []
        self._cache = cache
        self.dyldwalker = DyldWalker(cache, cache_symbols=cache_symbols)

    def index(self, verbose=False):
        """ indexes the addresses """
        self.dyldwalker.walk_segments(self._callback, verbose=verbose)

    def get_export_name_for_addr(self, addr):
        return self.dyldwalker.get_export_name_for_addr(addr)

    def get_addresses(self):
        """ gets the addresses with the following order:
           vmaddr, vmsize, dylibPath, offsetWithinTheDyldFile """
        return self._addrs

    def _callback(self, macho_file, dylib_path, seg, slide, dsc_offset):
        self._addrs.append((seg.vmaddr,
                            seg.vmsize,
                            dylib_path,
                            seg.fileoff,
                            dsc_offset))


class AddrFinder:
    """ finds if a given virtual address is found within the mapped dyld
        cache """
    def __init__(self, cache, cache_symbols):
        self._cache = cache
        self.result = None
        self.indexer = AddressesIndexer(self._cache, cache_symbols)
        self.indexer.index()

    def get_export_name_for_addr(self, addr):
        return self.indexer.get_export_name_for_addr(addr)

    def find(self, addr, verbose=False):
        """ returns offset within the dyld cache for given virtual address """
        for parts in self.indexer.get_addresses():
            vmaddr, vmsize, dylib_path, macho_offset, dsc_offset = parts
            if verbose:
                print "[+] find | 0x%08X: %s" % (vmaddr, dylib_path)
            if vmaddr <= addr < (vmaddr + vmsize):
                addr_offset_in_macho = addr - vmaddr
                return dylib_path, dsc_offset, addr_offset_in_macho


def decode_branch(opcode):
    sign = opcode & (1 << 25)
    offset = (opcode & 0x01ffffff) * 4
    if sign:
        print "sign!"
        offset -= 0x08000000
    return hex(offset)


def encode_branch(offset):
    if offset < -0x08000000 or offset > 0x07fffffc:
        raise("big number!", offset)
    ret = 0x14000000
    if offset < 0:
        ret = 0x16000000
        offset += 0x08000000

    return ret | (offset/4)


def isprintable(s, codec='utf8'):
    """ returns whether the given string is printable """
    try:
        s.decode(codec)
    except UnicodeDecodeError:
        return False
    except KeyboardInterrupt:
        raise
    return True


def get_next_bad_addr(curEa, regex_query):
    """ gets the next unmapped address offset for given EA in IDA """
    toJump = 0
    ea = curEa
    while ea <= curEa and ea != idc.BADADDR:
        toJump += 4
        ea = idc.FindText(curEa+toJump, idc.SEARCH_DOWN | idc.SEARCH_REGEX,
                          0,
                          0,
                          regex_query)
        if toJump >= 0x100:
            return idc.BADADDR
    return ea


def get_bad_addresses(verbose=True):
    """ gets all the unmapped addressed from IDA's database """
    ret = []
    curEa = idc.MinEA()
    while True:
        if verbose:
            print "[+] getting more bad addresses 0x%08X" % (curEa)
        # the regex "(DC[DQ]| B.*) +0x" will retrieve the following:
        # 1. DCD 0x...
        # 2. DCQ 0x...
        # 3. B   0x.....
        # 4. BL  0x....
        curEa = get_next_bad_addr(curEa, "(DC[DQ]| B.*) +0x")
        if curEa == idc.BADADDR:
            break
        if verbose:
            print "[+] found bad address at 0x%08X" % (curEa)
        dcd = idc.GetDisasm(curEa)
        res = re.findall("0x\w{8,}", dcd)
        for r in res:
            ret.append(int(r, 16))
    if verbose:
        print "[+] found %d bad addresses" % len(ret)
    return ret


def get_segments_and_exports_for_addresses(addresses, adrfind, verbose=True):
    """ for each address given, it returns it's segment size, and type """
    segments = []
    exports = []
    i = 0
    for addr in addresses:
        i += 1
        if verbose:
            print "[+] classifying other bad addresses: %d / %d" % (i, len(addresses))
        res = adrfind.find(addr)
        if res is None:
            print "[X] 0x%08X" % (addr)
            continue
        dylib_path, dsc_offset, macho_offset = res
        adrfind._cache.seek(dsc_offset + macho_offset)

        # if it's a string
        res = readcstr(adrfind._cache)
        if res and res.strip():
            segments.append((addr, len(res)+1, [(addr, len(res)+1, dsc_offset + macho_offset)]))
            continue

        # if it's an exported function
        export_name = adrfind.get_export_name_for_addr(addr)
        if export_name:
            exports.append((addr, export_name))
            continue

        # treat it like data
        size = 4
        segments.append((addr, size, [(addr, size, dsc_offset + macho_offset)]))
    return segments, exports


def join_neighbors(arr, threshold):
    """ joins near segments in the array if their gaps are less then the
        threshold """
    ret = []
    stack = arr[:]
    while stack:
        segment = stack.pop(0)
        segaddr, segsize, segdata = segment

        if not stack:
            ret.append(segment)
            break

        nextsegment = stack.pop(0)
        nextsegaddr, nextsegsize, nextsegdata = nextsegment

        gapsize = nextsegaddr - (segaddr + segsize)
        # if the gap (space) size is smaller than threshold
        if gapsize < threshold:
            # join segments
            newsize = nextsegaddr + nextsegsize - segaddr
            if newsize <= 0:
                raise RuntimeError("[!] got negative segment size")
            # push the joined back into the stack
            stack.insert(0, (segaddr, newsize, segdata + nextsegdata))
        else:
            # put it back in
            stack.insert(0, nextsegment)
            ret.append(segment)
    return ret


def normalize_export_name(name):
    if not name:
        return "no_name"
    toreplace = ['<', '>', '?', '!']
    for c in toreplace:
        name = name.replace(c, '_')
    return name


def make_islands_xrefs_force_bl_call(ea, verbose=True):
    """ makes all BL references to a branch islands as call """
    segname = idc.SegName(ea)
    if verbose:
        print "[+] forcing bl call on: %s [0x%X]" % (segname, ea)
    if "branch_islands" in segname:
        idc.SetFunctionFlags(ea, idc.GetFunctionFlags(ea) & (0xffffffff - 1))
        for x in idautils.XrefsTo(ea):
            make_islands_xrefs_force_bl_call(x.frm)
        return
    idc.ArmForceBLCall(ea)


def map_shared_bridges(dsc_file, adrfind):
    """ finds branch islands in a given dyld_shared_cache file,
        maps them to IDA's db and extract its addresses """
    dsc_file.seek(0, 2)
    filesize = dsc_file.tell()
    dsc_file.seek(0)
    ACCESS_READ = 1
    a = mmap.mmap(dsc_file.fileno(), length=filesize, access=ACCESS_READ)
    reexp = re.compile("\xcf\xfa\xed\xfe.{340,360}dyld_shared_cache_branch_islands")
    print "[+] scanning dsc for BRANCH ISLANDS"
    # this list will hold all our branch_islands segments
    branch_islands_segments = []
    jmp_to_code = collections.defaultdict(list)
    for ma in reexp.finditer(a):
        print "[+] WRITING BRANCH ISLAND: 0x%08X" % (ma.start())
        fif = FileInFile(dsc_file, ma.start())
        m = MachO_patched(fif)
        if _IN_IDA:
            for seg in m.segments:
                for sec in seg.sections:
                    idc.AddSegEx(sec.addr,
                                 sec.addr + sec.size, 0, 0,
                                 idaapi.saRelPara, idaapi.scPub,
                                 idc.ADDSEG_FILLGAP)
                    name = "branch_islands_%X%s%s" % (ma.start(), seg.segname, sec.sectname)
                    idc.RenameSeg(sec.addr, name)
                    idc.SetSegClass(sec.addr, "CODE")
                    idc.SetSegAddressing(sec.addr, 2)
                    dsc_file.seek(sec.offset)
                    memcpy(sec.addr, dsc_file.read(sec.size))
                    branch_islands_segments.append(sec.addr)
                    # make code
                    codeea = sec.addr
                    print "Going through the code!"
                    while codeea < (sec.addr + sec.size):
                        res = idc.MakeCode(codeea)
                        if not res:
                            print "[!] EA:0x%X ERR while making code" % codeea
                            codeea += 4
                            continue

                        d = idc.GetDisasm(codeea)
                        # if it's a "B     0x4dd13550"
                        if d.startswith("B "):
                            addr = d.split()[1]
                            if addr.startswith("0x"):
                                branchaddr = int(addr, 16)
                                jmp_to_code[branchaddr].append(codeea)
                                #   idc.MakeRptCmt(codeea, "0x%X was taken!" % branchaddr)

                        codeea = idc.FindUnexplored(codeea, idc.SEARCH_DOWN)
    label_and_fix_branch_islands(dsc_file, adrfind, jmp_to_code)


def label_and_fix_branch_islands(dsc_file, adrfind, jmp_to_code):
    """ labels, comments and fixes code flow on branch islands """
    jmpaddrs = sorted(set(jmp_to_code.keys()))
    dsc_file.seek(0)
    header = dsc_header(dsc_file)
    dsc_file.seek(header.images_offset)
    i = 0
    jmpaddrslen = len(jmpaddrs)
    for addr in jmpaddrs:
        print "status: 0x%X %d/%d" % (addr, i, jmpaddrslen)
        res = adrfind.find(addr)
        if not res:
            print "[!] coudln't find addr for addr:", addr
        dylib_path, dsc_offset, macho_offset = res
        exportname = adrfind.get_export_name_for_addr(addr)
        if _IN_IDA:
            eas = jmp_to_code[addr]
            for ea in eas:
                idc.MakeRptCmt(ea, "%s'%s" % (dylib_path, exportname))
                if "branch_islands" in idc.SegName(ea):
                    make_name(ea, exportname)
                    # patch them to "RET" so they would return
                    memcpy(ea, "\xC0\x03\x5F\xD6")
                    make_islands_xrefs_force_bl_call(ea)
        else:
            print "[+] \\\\ %s" % exportname
        i += 1


def memcpy(addr, data):
    """ writes data to the virtual address in IDA's database """
    for i in xrange(0, len(data)):
        idc.PatchByte(addr + i, ord(data[i]))


def map_segments(segments, dsc_file, verbose=True):
    for segaddr, segsize, segdata in segments:
        print "[+] creating seg: 0x%08X: %d" % (segaddr, segsize)
        # check that there are no existing segments in that address
        if idc.SegStart(segaddr) == idc.BADADDR:
            idc.AddSegEx(segaddr,
                         segaddr + segsize, 0, 0,
                         idaapi.saRelPara, idaapi.scPub,
                         idc.ADDSEG_FILLGAP)
            # set it as read-only
            idc.SetSegmentAttr(segaddr, idc.SEGATTR_PERM, SEGPERM_READ)
        else:
            print "[!] Skipping creation of existing segment.."

        # after mapping the segment, write the data to the db.
        try:
            for addr, size, macho_offset in segdata:
                dsc_file.seek(macho_offset)
                memcpy(addr, dsc_file.read(size))
                if verbose:
                    print "0x%X, 0x%06X, 0x%06X: %s" % (addr,
                                                        size,
                                                        macho_offset,
                                                        dsc_file.read(size))
        except Exception:
            print segdata
            raise


def make_name(addr, export_name):
    """ Appends a number if a given name exists """
    ret = idc.MakeNameEx(addr, export_name, idc.SN_PUBLIC | idc.SN_NOWARN)
    i = 0
    while ret == 0 and i < 1000:
        new_name = "%s_%d" % (export_name, i)
        ret = idc.MakeNameEx(addr, new_name, idc.SN_PUBLIC | idc.SN_NOWARN)
        i += 1

    if ret == 0:
        print "[!] could not set name %s at 0x%X" % (export_name, addr)


def map_exports(exports, verbose=True):
    """ gets an array of [(vaddress, name),..] and writes it to db"""
    if verbose:
        print "[+] going for %d exports" % (len(exports))
    for addr, export_name in exports:
        print "[+] creating export", export_name
        # check that there are no existing segments in that address
        if idc.SegStart(addr) == idc.BADADDR:
            print "[+] creating seg: 0x%08X: %d" % (addr, 4)
            idc.AddSegEx(addr,
                         addr + 4, 0, 0,
                         idaapi.saRelPara, idaapi.scPub,
                         idc.ADDSEG_FILLGAP)
        elif verbose:
            print "[!] Skipping creation of existing segment.."
        # set it as execuable
        idc.SetSegmentAttr(addr, idc.SEGATTR_PERM, SEGPERM_EXEC)
        if verbose:
            print "[+] making name: %s" % (export_name)
        make_name(addr, export_name)


def main():
    if _IN_IDA:
        # # get dyld_shared_cache path from IDA's openFile dialog
        print "[+] Please choose the original dyld_shared_cache_arm64"
        dsc_path = idc.AskFile(0, "*.*", "dyld shared cache file")
    else:
        dsc_path = sys.argv[1]

    if not dsc_path or not os.path.exists(dsc_path):
        raise RuntimeError("Couldn't find the dyld shared cache file..")

    print "[+] about to parse %s.." % (dsc_path)
    dsc_file = open(dsc_path, "rb")
    adrfind = AddrFinder(dsc_file, cache_symbols=False)
    map_shared_bridges(dsc_file, adrfind)
    if _IN_IDA:
        addresses = sorted(set(get_bad_addresses()))
    else:
        addresses = sorted(set(eval(open("addrs.txt", "rb").read())))

    segments, exports = get_segments_and_exports_for_addresses(addresses, adrfind)
    # segments = join_neighbors(segments, threshold=0x1000)
    if _IN_IDA:
        map_segments(segments, dsc_file)
        map_exports(exports)
        idaapi.analyze_area(idc.MinEA(), idc.MaxEA())


if __name__ == "__main__":
    main()
