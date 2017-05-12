import binascii 
import immlib
import random
import struct
from immlib import LogBpHook
from time import gmtime, strftime
from libheap import *	

'''
java-dumper project (for 32 bit executable files)
'''

MAGIC = binascii.unhexlify("CAFEBABE")

CONSTANT_Class				= 7
CONSTANT_Fieldref 			= 9
CONSTANT_Methodref 			= 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String 			= 8
CONSTANT_Integer 			= 3
CONSTANT_Float 				= 4
CONSTANT_Long 				= 5
CONSTANT_Double 			= 6
CONSTANT_NameAndType 		= 12
CONSTANT_Utf8 				= 1
CONSTANT_MethodHandle 		= 15
CONSTANT_MethodType 		= 16
CONSTANT_InvokeDynamic 		= 18

# set random generator
random.seed()

def get_size(fmt):
	return struct.calcsize(fmt)

class java_class:
	def __init__(self, imm, buf, verbose):
		self.body = dict()
		self.imm = imm
		self.verbose = verbose
		self.buf = buf
		self.buf_copy = buf
		self.size = 0
		self.cp_infos = ''
		self.fields_count = None
		self.fields = None
		self.attributes_count = None
		self.attributes = None

	def create_class_file(self, filename, size):
		with open(filename, "wb") as file:
			file.write(self.buf_copy[:size])

	def update_buf(self, fmt):
		self.buf = self.buf[struct.calcsize(fmt):]
		self.size += struct.calcsize(fmt)

	def parse_methods(self, methods_count):
		while methods_count > 0:
			method_info = dict()
			method_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("method access flags: 0x%04X" % method_info['access_flags'])
			self.update_buf('H')
			method_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("method name index: 0x%04X" % method_info['name_index'])
			self.update_buf('H')
			method_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:	
				self.imm.log("method descriptor index: 0x%04X" % method_info['descriptor_index'])
			self.update_buf('H')
			method_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("method attributes count: 0x%04X" % method_info['attributes_count'])
			self.update_buf('H')
			self.parse_attributes(method_info['attributes_count'])
			methods_count -= 1

	def parse_attributes(self, attributes_count):
		while attributes_count > 0:
			attribute_info = dict()
			attribute_info['attribute_name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("attribute name index: 0x%04X" % attribute_info['attribute_name_index'])
			self.update_buf('H')
			attribute_info['attribute_length'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
			if self.verbose:
				self.imm.log("attribute length: 0x%08X" % attribute_info['attribute_length'])
			self.update_buf('I')
			attribute_info['info'] = self.buf[:attribute_info['attribute_length']] 
			if self.verbose:	
				self.imm.log("info: %s" % " ".join("%02X" % ord(el) for el in (attribute_info['info'])))
			self.buf = self.buf[attribute_info['attribute_length']:]
			self.size += attribute_info['attribute_length']
			attributes_count -= 1

	def parse_fields(self, fields_count):
		while fields_count > 0:
			field_info = dict()
			field_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("access flags: 0x%04X" % field_info['access_flags'])
			self.update_buf('H')
			field_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("name index: 0x%04X" % field_info['name_index'])
			self.update_buf('H')
			field_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("descriptor index: 0x%04X" % field_info['descriptor_index'])
			self.update_buf('H')
			field_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			if self.verbose:
				self.imm.log("attributes count: 0x%04X" % field_info['attributes_count'])
			self.update_buf('H')
			self.parse_attributes(field_info['attributes_count'])
			fields_count -= 1

	def parse_cp_info(self, constant_pool_count):
		counter = constant_pool_count - 1
		while counter > 0:
			if self.verbose:
				self.imm.log('[*] Counter = %d' % counter)
				self.imm.log('-'*10)
			cp_info = dict()
			# get tag
			cp_info['tag'] = struct.unpack('B', self.buf[:get_size('B')])[0]
			self.update_buf('B')
			# switch tag
			# CONSTANT_Class
			if cp_info['tag']  == CONSTANT_Class:
				cp_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_Fieldref
			elif cp_info['tag']  == CONSTANT_Fieldref:
				cp_info['class_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['name_and_type_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_Methodref
			elif cp_info['tag']  == CONSTANT_Methodref:
				cp_info['class_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['name_and_type_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_InterfaceMethodref
			elif cp_info['tag']  == CONSTANT_InterfaceMethodref:
				cp_info['class_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['name_and_type_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_String
			elif cp_info['tag']  == CONSTANT_String:
				cp_info['string_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_Integer
			elif cp_info['tag']  == CONSTANT_Integer:
				cp_info['bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
			# CONSTANT_Float
			elif cp_info['tag']  == CONSTANT_Float:
				cp_info['bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
			# CONSTANT_Long
			elif cp_info['tag']  == CONSTANT_Long:
				cp_info['high_bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
				cp_info['low_bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
			# CONSTANT_Double_info
			elif cp_info['tag']  == CONSTANT_Double:
				cp_info['high_bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
				cp_info['low_bytes'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
				self.update_buf('I')
			# CONSTANT_NameAndType
			elif cp_info['tag']  == CONSTANT_NameAndType:
				cp_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_Utf8
			elif cp_info['tag']  == CONSTANT_Utf8:
				cp_info['length'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['bytes'] = self.buf[:cp_info['length']]
				self.buf = self.buf[cp_info['length']:]
				self.size += cp_info['length']
			# CONSTANT_MethodHandle 
			elif cp_info['tag']  == CONSTANT_MethodHandle:
				cp_info['reference_kind'] = struct.unpack('B', self.buf[:get_size('B')])[0]
				self.update_buf('B')
				cp_info['reference_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_MethodType
			elif cp_info['tag']  == CONSTANT_MethodType:
				cp_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			# CONSTANT_InvokeDynamic
			elif cp_info['tag']  == CONSTANT_InvokeDynamic:
				cp_info['bootstrap_method_attr_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
				cp_info['name_and_type_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
				self.update_buf('H')
			else:
				raise Exception('[-] Unsupported tag: %d\n[*] chunk has dumped' % cp_info['tag'])
			# update counter
			counter -= 1
			# store info
			for key, value in cp_info.iteritems():
				el = key + ' : ' + str(value) + '\n'
				self.cp_infos += el
				if verbose:
					self.imm.log(key + ' : ' + str(value))
			self.imm.log('-'*10)

	@classmethod
	def unpack(cls, imm, buf, to_end_size, class_addr, verbose):
		cls = cls(imm, buf, verbose)
		try:
			# get magic
			if cls.verbose:
				cls.imm.log('[*] unpacking magic')
			cls.body['magic'] = struct.unpack('>I', cls.buf[:get_size('I')])[0]
			cls.update_buf('I')
			if cls.verbose:
				cls.imm.log("magic: 0x%04X" % cls.body['magic'])
			# get minor version
			if cls.verbose:
				cls.imm.log('[*] unpacking minor version')
			cls.body['minor_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("minor version: 0x%04X" % cls.body['minor_version'])
			# get major version
			if cls.verbose:
				cls.imm.log('[*] unpacking major version')
			cls.body['major_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("major version: 0x%04X" % cls.body['major_version'])
			# get constant pool count
			if cls.verbose:
				cls.imm.log('[*] unpacking constant pool count')
			cls.body['constant_pool_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("constant pool count: 0x%04X" % cls.body['constant_pool_count'])
			# get constant pool
			if cls.verbose:
				cls.imm.log('[*] unpacking constant pool')
			cls.parse_cp_info(cls.body['constant_pool_count'])
			# get access flags
			if cls.verbose:
				cls.imm.log('[*] unpacking access flags')
			cls.body['access_flags'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("access flags: 0x%04X" % cls.body['access_flags'])
			# get this class
			if cls.verbose:
				cls.imm.log('[*] unpacking this class')
			cls.body['this_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("this class: 0x%04X" % cls.body['this_class'])
			# get super class
			if cls.verbose:
				cls.imm.log('[*] unpacking super class')
			cls.body['super_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:	
				cls.imm.log("super class: 0x%04X" % cls.body['super_class'])
			# get interfaces count
			if cls.verbose:
				cls.imm.log('[*] unpacking interfaces count')
			cls.body['interfaces_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("interfaces count: 0x%04X" % cls.body['interfaces_count'])
			if cls.verbose:
				cls.imm.log('[*] unpacking interfaces')
			cls.body['interfaces'] = cls.buf[:cls.body['interfaces_count'] * 2]
			cls.buf = cls.buf[cls.body['interfaces_count'] * 2:]
			cls.size += cls.body['interfaces_count'] * 2
			if cls.verbose:
				cls.imm.log("interfaces: %s" % " ".join("%02X" % ord(el) for el in cls.body['interfaces']))
			# get fields count
			if cls.verbose:
				cls.imm.log('[*] unpacking fields count')
			cls.body['fields_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			if cls.verbose:
				cls.imm.log("fields count: 0x%04X" % cls.body['fields_count'])
			cls.update_buf('H')
			# get fields
			cls.parse_fields(cls.body['fields_count'])
			# get methods count
			if cls.verbose:
				cls.imm.log('[*] unpacking methods count')
			cls.body['methods_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("methods count: 0x%04X" % cls.body['methods_count'])
			# get methods
			cls.parse_methods(cls.body['methods_count'])
			# get attributes count
			if cls.verbose:
				cls.imm.log('[*] unpacking attributes count')
			cls.body['attributes_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
			cls.update_buf('H')
			if cls.verbose:
				cls.imm.log("attributes count: 0x%04X" % cls.body['attributes_count'])
			# get attributes
			cls.parse_attributes(cls.body['attributes_count'])
			# creating java class (filename is chosen as current time value)
			filename = strftime("%Y-%m-%d %H:%M:%S", gmtime()).translate(None, ':- ') + "_" + str(random.randint(0, 0xFFFFFFFF)) + ".class"
			cls.create_class_file(filename, cls.size)
			if cls.verbose:
				cls.imm.log('[+] Class file has written')
			cls.imm.log('[+] java class at address 0x%08X is collected with size %d', class_addr, j_class.size)
		except:
			# java class is not full loaded
			filename = strftime("%Y-%m-%d %H:%M:%S", gmtime()).translate(None, ':- ') + "_" + str(random.randint(0, 0xFFFFFFFF)) + "_dumped.class"
			cls.create_class_file(filename, to_end_size)
			imm.log('[*] java class is not full loaded in ROM (dumped)')
		return cls

	def __str__(self):
		result = ''
		for field, value in self.body.items():
			result += field + ' : ' + hex(value) + '\n'
		result += self.cp_infos
		return result


class CloseHandle_Hooker(LogBpHook):
	def __init__(self, verbose):
		LogBpHook.__init__(self)
		self.filename = None
		self.verbose = verbose

	def get_java_class(self, imm, buf, class_addr, to_end_size):
		j_class = java_class.unpack(imm, buf, to_end_size, class_addr, self.verbose)
		return j_class

	def check_java_class(self, imm, buf, chunk):
		while MAGIC in buf:
			message = '[+] Found class in chunk at address 0x%08X' % chunk.addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.flashMessage(message)
			offset = buf.find(MAGIC)
			buf = buf[offset:]
			class_addr = chunk.addr + offset
			message = '[+] Java class address: 0x%08X' % class_addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.log('[*] trying to parse java class')
			j_class = self.get_java_class(imm, buf, class_addr, chunk.size - offset)
			buf = buf[j_class.size:]
		else:
			pass

	def scan_heaps(self, imm):
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			for chunk in pheap.chunks:
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, data, chunk)

	def get_call_params(self, regs):
		hObject = regs['ESP'] + 4
		return hObject

	def run(self, regs):
		imm = immlib.Debugger()
		self.regs = regs
		imm.log('[+] Captured CloseHandle hook ')
		imm.log('------------------------------')
		# Collect ReadFile params
		hObject = self.get_call_params(regs)
		handle = struct.unpack("<I", imm.readMemory(hObject, 4))[0]
		imm.log("[*] Close handle %d" % handle)
		self.scan_heaps(imm)
		imm.log('------------------------------')


class ReadFile_Hooker(LogBpHook):
	def __init__(self, verbose):
		LogBpHook.__init__(self)
		self.filename = None
		self.verbose = verbose

	def get_java_class(self, imm, buf, class_addr, to_end_size):
		j_class = java_class.unpack(imm, buf, to_end_size, class_addr, self.verbose)
		imm.log('[+] java class at address 0x%08X is collected with size %d', class_addr, j_class.size)
		return j_class

	def check_java_class(self, imm, buf, chunk):
		while MAGIC in buf:
			message = '[+] Found class in chunk at address 0x%08X' % chunk.addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.flashMessage(message)
			offset = buf.find(MAGIC)
			buf = buf[offset:]
			class_addr = chunk.addr + offset
			message = '[+] Java class address: 0x%08X' % class_addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.log('[*] trying to parse java class')
			j_class = self.get_java_class(imm, buf, class_addr, chunk.size - offset)
			buf = buf[j_class.size:]
		else:
			pass

	def scan_heaps(self, imm):
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			for chunk in pheap.chunks:
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, data, chunk)

	def get_call_params(self, regs):
		hFile = regs['ESP'] + 4
		lpBuffer = regs['ESP'] + 8
		nNumberOfBytesToRead = regs['ESP'] + 12
		lpNumberOfBytesRead = regs['ESP'] + 16
		lpOverlapped = regs['ESP'] + 20
		return [hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped]

	def run(self, regs):
		imm = immlib.Debugger()
		self.regs = regs
		imm.log('[+] Captured ReadFile hook ')
		imm.log('------------------------------')
		# Collect ReadFile params
		rFparams = self.get_call_params(regs)
		handle = struct.unpack("<I", imm.readMemory(rFparams[0], 4))[0][0]
		imm.log("[*] ReadFile by handle %d" % handle)
		imm.log('------------------------------')
		self.scan_heaps(imm)


class CreateFileW_Hooker(LogBpHook):
	def __init__(self, verbose):
		LogBpHook.__init__(self)
		self.filename = None
		self.verbose = verbose

	def get_java_class(self, imm, buf, class_addr, to_end_size):
		j_class = java_class.unpack(imm, buf, to_end_size, class_addr, self.verbose)
		imm.log('[+] java class at address 0x%08X is collected with size %d' % (class_addr, j_class.size))
		return j_class 

	def check_java_class(self, imm, buf = None, chunk = None, is_addr = False, addr = None):
		if not is_addr:
			while MAGIC in buf:
				message = '[+] Found class in chunk at address 0x%08X' % chunk.addr
				imm.log(message)
				imm.flashMessage(message)
				offset = buf.find(MAGIC)
				buf = buf[offset:]
				class_addr = chunk.addr + offset
				message = '[+] Java class address: 0x%08X' % class_addr
				imm.log(message)
				imm.log('[*] trying to parse java class')
				j_class = self.get_java_class(imm, buf, class_addr, chunk.size - offset)
				buf = buf[j_class.size:]
			else:
				pass
		else:
			message = '[+] Found java class at address 0x%08X in writeable memory' % addr
			imm.log(message)
			imm.flashMessage(message)
			buf = imm.readMemory(addr, 1000000)
			j_class = self.get_java_class(imm, buf, addr, len(buf))

	def scan_heaps(self, imm):
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			for chunk in pheap.chunks:
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, buf = data, chunk = chunk)

	def scan_WIN32_heaps(self,imm):
		# get all heaps
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			# get all chunks in current heap
			chunks = pheap.getChunks(0)
			for chunk in chunks:
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, buf = data, chunk = chunk)

	def scan_writeable_memory(self,imm):
		# search for a MAGIC in writable memory
		java_class_addrs = imm.searchOnWrite(MAGIC) 
		for addr in java_class_addrs:
			self.check_java_class(imm, is_addr = True, addr = addr)
	
	def get_filename(self, imm, addr):
		filename = ""
		filename = imm.readWString(addr)
		self.filename = filename

	def get_call_params(self, regs):
		lpFileName = regs['ESP'] + 4
		dwDesiredAccess = regs['ESP'] + 8
		dwShareMode = regs['ESP'] + 12
		lpSecurityAttributes = regs['ESP'] + 16
		dwCreationDisposition = regs['ESP'] + 20
		dwFlagsAndAttributes = regs['ESP'] + 24
		hTemplateFile = regs['ESP'] + 28
		return [lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile]

	def run(self, regs):
		imm = immlib.Debugger()
		self.regs = regs
		imm.log('[+] Captured CreateFileW hook ')
		imm.log('------------------------------')
		# Collect CreateFileW params
		crFparams = self.get_call_params(regs)
		filename_ptr = struct.unpack("<I", imm.readMemory(crFparams[0], 4))[0]
		imm.log("[*] filename_ptr = %08X" % filename_ptr)
		self.get_filename(imm, filename_ptr)
		if ".jar" in self.filename:
			imm.log("[+] got %s" % self.filename)
		imm.log('------------------------------')
		# commented to test another API function
		#self.scan_heaps(imm)
		#self.scan_WIN32_heaps(imm)
		self.scan_writeable_memory(imm)


def init_hooks(imm, args):
	# check verbosity
	if '-v' in args:
		verbose = True
	else:
		verbose = False
	CreateFileW_addr = imm.getAddress("kernel32.CreateFileW")
	ReadFile_addr = imm.getAddress("kernel32.ReadFile")
	CloseHandle_addr = imm.getAddress("kernel32.CloseHandle")
	# catch CreateFileW calls
	if args[0] == '-s':
		whook = CreateFileW_Hooker(verbose)
		whook.add("bp_on_kernel32.CreateFileW", CreateFileW_addr)
	# catch ReadFile calls
	if args[0] == '-i':
		rhook = ReadFile_Hooker(verbose)
		rhook.add("bp_on_kernel32.ReadFile", ReadFile_addr)
	# catch CloseHandle calls
	if args[0] == '-f':
		chook = CloseHandle_Hooker(verbose)
		chook.add("bp_on_kernel32.CloseHandle", CloseHandle_addr)


def usage(imm):
	imm.log(10 * '#' + ' Immunity Debugger java dumper ' + 10 * '#')
	imm.log("!java-dumper [-s] [-i] [-f] [-v]              ")
	imm.log("              -s   standart scan, checks each CreateFileW call               ")
	imm.log("              -i   intensive scan, [-s] plus checks each ReadFile call       ")
	imm.log("              -f   full scan, [-s, -i] plus checks each CloseHandle call     ")
	imm.log("              -v	show full info about parsed java class fiels     ")


def main(args): 
	imm = immlib.Debugger()
	if not args and len(args) != 1:
		usage(imm)
		return "[-] no arguments"
	else:
		init_hooks(imm, args)
	return "[+] done"
