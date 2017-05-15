import binascii 
import immlib
import getopt
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
CONSTANT_Fieldref			= 9
CONSTANT_Methodref			= 10
CONSTANT_InterfaceMethodref	= 11
CONSTANT_String				= 8
CONSTANT_Integer			= 3
CONSTANT_Float				= 4
CONSTANT_Long				= 5
CONSTANT_Double				= 6
CONSTANT_NameAndType		= 12
CONSTANT_Utf8				= 1
CONSTANT_MethodHandle		= 15
CONSTANT_MethodType			= 16
CONSTANT_InvokeDynamic		= 18

CLASS_MAX_SIZE = 65536

# set random generator
random.seed()


def get_size(fmt):
	return struct.calcsize(fmt)


def BE_bytes(fmt, value):
	return struct.unpack('>' + fmt, value)[0]


def bin2hex(raw):
	return " ".join("%02X" % ord(el) for el in raw)


class JavaClassOverflowException(Exception):
     def __init__(self, size):
         self.message = "[-] java class is too big: %s bytes" % size 
     
     def __str__(self):
         return repr(self.message)


class java_class:
	def __init__(self, imm, class_addr, verbose):
		self.imm = imm
		self.filename = None
		self.class_addr = class_addr
		self.class_buf = ''
		self.size = 0
		self.body = []
		self.cur_value = None
		self.verbose = verbose

	def generate_filename(self):
		self.filename = strftime("%Y%m%d%H%M%S", gmtime()) + "_" + str(random.randint(0, 0xFFFFFFFF)) + ".class"
		return

	def create_class_file(self):
		with open(self.filename, "wb") as file:
			file.write(self.class_buf)

	def check_size(self, size):
		if self.size + size >= CLASS_MAX_SIZE:
			raise JavaClassOverflowException(self.size + size)

	def get_memory(self, fmt, field_name, raw = False, size = False):
		if not raw:
			value = self.imm.readMemory(self.class_addr, get_size(fmt))
			self.class_buf += value
			self.cur_value = BE_bytes(fmt, value)
			self.body.append((field_name, self.cur_value))
			self.size += get_size(fmt)
			self.class_addr += get_size(fmt)
		else:
			value = self.imm.readMemory(self.class_addr, size)
			self.class_buf += value
			self.body.append((field_name, bin2hex(value)))
			self.size += size
			self.class_addr += size
		if self.size > CLASS_MAX_SIZE:
			raise JavaClassOverflowException(self.size)

	def parse_methods(self, methods_count):
		counter = methods_count
		while counter > 0:
			self.get_memory('H', 'access_flags')
			self.get_memory('H', 'name_index')
			self.get_memory('H', 'descriptor_index')
			self.get_memory('H', 'attributes_count')
			self.parse_attributes(self.cur_value)
			counter -= 1

	def parse_attributes(self, attributes_count):
		counter = attributes_count
		while counter > 0:
			self.get_memory('H', 'attribute_name_index')
			self.get_memory('I', 'attribute_length')
			self.get_memory(None, 'info', raw = True, size = self.cur_value)
			counter -= 1

	def parse_fields(self, fields_count):
		counter = fields_count
		while counter > 0:
			self.get_memory('H', 'access_flags')
			self.get_memory('H', 'name_index')
			self.get_memory('H', 'descriptor_index')
			self.get_memory('H', 'attributes_count')
			self.parse_attributes(self.cur_value)
			counter -= 1

	def parse_cp_info(self, constant_pool_count):
		counter = constant_pool_count - 1
		while counter > 0:
			if self.verbose:
				self.imm.log('[*] Counter = %d' % counter)
			# get tag
			self.get_memory('B', 'tag')
			# CONSTANT_Class
			if self.cur_value  == CONSTANT_Class:
				self.get_memory('H', 'name_index')
			# CONSTANT_Fieldref
			elif self.cur_value  == CONSTANT_Fieldref:
				self.get_memory('H', 'class_index')
				self.get_memory('H', 'name_and_type_index')
			# CONSTANT_Methodref
			elif self.cur_value  == CONSTANT_Methodref:
				self.get_memory('H', 'class_index')
				self.get_memory('H', 'name_and_type_index')
			# CONSTANT_InterfaceMethodref
			elif self.cur_value  == CONSTANT_InterfaceMethodref:
				self.get_memory('H', 'class_index')
				self.get_memory('H', 'name_and_type_index')
			# CONSTANT_String
			elif self.cur_value  == CONSTANT_String:
				self.get_memory('H', 'string_index')
			# CONSTANT_Integer
			elif self.cur_value  == CONSTANT_Integer:
				self.get_memory('I', 'bytes')
			# CONSTANT_Float
			elif self.cur_value  == CONSTANT_Float:
				self.get_memory('I', 'bytes')
			# CONSTANT_Long
			elif self.cur_value  == CONSTANT_Long:
				self.get_memory('I', 'high_bytes')
				self.get_memory('I', 'low_bytes')
			# CONSTANT_Double_info
			elif self.cur_value  == CONSTANT_Double:
				self.get_memory('I', 'high_bytes')
				self.get_memory('I', 'low_bytes')
			# CONSTANT_NameAndType
			elif self.cur_value  == CONSTANT_NameAndType:
				self.get_memory('H', 'name_index')
				self.get_memory('H', 'descriptor_index')
			# CONSTANT_Utf8
			elif self.cur_value  == CONSTANT_Utf8:
				self.get_memory('H', 'length')
				self.get_memory(None, 'bytes', raw = True, size = self.cur_value)
			# CONSTANT_MethodHandle 
			elif self.cur_value  == CONSTANT_MethodHandle:
				self.get_memory('B', 'reference_kind')
				self.get_memory('H', 'reference_index')
			# CONSTANT_MethodType
			elif self.cur_value  == CONSTANT_MethodType:
				self.get_memory('H', 'descriptor_index')
			# CONSTANT_InvokeDynamic
			elif self.cur_value  == CONSTANT_InvokeDynamic:
				self.get_memory('H', 'bootstrap_method_attr_index')
				self.get_memory('H', 'name_and_type_index')
			else:
				raise Exception('[-] Unsupported tag: %d\n' % self.cur_value)
			# update counter
			counter -= 1

	@classmethod
	def unpack(cls, imm, class_addr, verbose = False):
		cls = cls(imm, class_addr, verbose)
		try:
			# get magic
			if cls.verbose:
				cls.imm.log('[*] unpacking magic')
			cls.get_memory('I', 'magic')
			# get minor version
			if cls.verbose:
				cls.imm.log('[*] unpacking minor version')
			cls.get_memory('H', 'minor_version')
			# get major version
			if cls.verbose:
				cls.imm.log('[*] unpacking major version')
			cls.get_memory('H', 'major_version')
			# get constant pool count
			if cls.verbose:
				cls.imm.log('[*] unpacking constant pool count')
			cls.get_memory('H', 'constant_pool_count')
			# check constant_pool_count
			cls.check_size(cls.cur_value)
			# get constant pool
			if cls.verbose:
				cls.imm.log('[*] unpacking constant pool')
			cls.parse_cp_info(cls.cur_value)
			# get access flags
			if cls.verbose:
				cls.imm.log('[*] unpacking access flags')
			cls.get_memory('H', 'access_flags')
			# get this class
			if cls.verbose:
				cls.imm.log('[*] unpacking this class')
			cls.get_memory('H', 'this_class')
			# get super class
			if cls.verbose:
				cls.imm.log('[*] unpacking super class')
			cls.get_memory('H', 'super_class')
			# get interfaces count
			if cls.verbose:
				cls.imm.log('[*] unpacking interfaces count')
			cls.get_memory('H', 'interfaces_count')
			cls.check_size(cls.cur_value * 2)
			if cls.verbose:
				cls.imm.log('[*] unpacking interfaces')
			cls.get_memory(None, 'interfaces', raw = True, size = cls.cur_value * 2)
			# get fields count
			if cls.verbose:
				cls.imm.log('[*] unpacking fields count')
			cls.get_memory('H', 'fields_count')
			cls.check_size(cls.cur_value)
			# get fields
			cls.parse_fields(cls.cur_value)
			# get methods count
			if cls.verbose:
				cls.imm.log('[*] unpacking methods count')
			cls.get_memory('H', 'methods_count')
			cls.check_size(cls.cur_value)
			# get methods
			cls.parse_methods(cls.cur_value)
			# get attributes count
			if cls.verbose:
				cls.imm.log('[*] unpacking attributes count')
			cls.get_memory('H', 'attributes_count')
			cls.check_size(cls.cur_value)
			# get attributes
			cls.parse_attributes(cls.cur_value)
			# creating java class
			cls.generate_filename()
			cls.create_class_file()
			# end
			cls.imm.log('[+] java class %s is collected' % cls.filename)

		except JavaClassOverflowException:
			cls.imm.log('[-] java class is too big or freed')

		except Exception as e:
			cls.imm.log('[-] java class is broken')
		return cls
		
	def __str__(self):
		result = ''
		for item in self.body:
			result += item[0] + " : " + str(item[1])
		return result


class Hooker(LogBpHook):
	def __init__(self, verbose, heaps_scan):
		LogBpHook.__init__(self)
		self.filename = None
		self.verbose = verbose
		self.heaps_scan = heaps_scan

	def get_java_class(self, imm, class_addr):
		j_class = java_class.unpack(imm, class_addr, verbose = self.verbose)
		return j_class 

	def check_java_class(self, imm, buf = None, chunk = None, is_addr = False, addr = None):
		if not is_addr:
			while MAGIC in buf:
				# find java class MAGIC
				offset = buf.find(MAGIC)
				# get java class address
				class_addr = chunk.addr + offset
				message = '[+] Found java class at address 0x%08X in heap' % class_addr
				imm.log(message)
				imm.flashMessage(message)
				imm.log('[*] trying to parse java class')
				# parse java class
				j_class = self.get_java_class(imm, class_addr)
				# get last chunk part
				buf = buf[j_class.size:]
			else:
				imm.log("[*] chunk doesn't contain any class file")
				pass
		else:
			message = '[+] Found java class at address 0x%08X in writeable memory' % addr
			imm.log(message)
			imm.flashMessage(message)
			j_class = self.get_java_class(imm, addr)

	def scan_WIN32_heaps(self,imm):
		# get all heaps
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			# get all chunks in current heap
			chunks = pheap.getChunks(0)
			for chunk in chunks:
				imm.log('[*] checking chunk at address 0x%08X' % chunk.addr)
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, buf = data, chunk = chunk)

	def scan_writeable_memory(self,imm):
		# search for a MAGIC in writable memory
		java_class_addrs = imm.searchOnWrite(MAGIC) 
		for addr in java_class_addrs:
			self.check_java_class(imm, is_addr = True, addr = addr)
	
	def get_filename(self, imm):
		filename = ""
		crFparams = self.get_call_params(self.regs)
		filename_ptr = struct.unpack("<I", imm.readMemory(crFparams[0], 4))[0]
		filename = imm.readWString(filename_ptr)
		self.filename = filename

	def run(self, regs):
		imm = immlib.Debugger()
		self.regs = regs
		# scan memory
		if self.heaps_scan:
			self.scan_WIN32_heaps(imm)
		else:
			self.scan_writeable_memory(imm)


def init_hooks(imm, opts):
	# init default parameters
	verbose = False
	heaps_scan = False
	# collect system functions addresses
	CreateFileW_addr = imm.getAddress("kernel32.CreateFileW")
	ReadFile_addr = imm.getAddress("kernel32.ReadFile")
	CloseHandle_addr = imm.getAddress("kernel32.CloseHandle")

	for o, _ in opts:
		# parse arguments
		if o == '-v':
		# enable verbosity
			verbose = True
			imm.log('[*] verbosity is enable')
		elif o == '-H':
		# enable heaps scan mode
			heaps_scan = True
			imm.log('[*] heaps scan mode is enabled')
		elif o == '-c':
			# catch CreateFileW calls
			whook = Hooker(verbose, heaps_scan)
			whook.add("bp_on_kernel32.CreateFileW", CreateFileW_addr)
			imm.log('[*] CreateFileW hook')
		elif o == '-r':
			# catch ReadFile calls
			rhook = Hooker(verbose, heaps_scan)
			rhook.add("bp_on_kernel32.ReadFile", ReadFile_addr)
			imm.log('[*] ReadFile hook')
		elif o == '-C':
			# catch CloseHandle calls
			chook = Hooker(verbose, heaps_scan)
			chook.add("bp_on_kernel32.CloseHandle", CloseHandle_addr)
			imm.log('[*] CloseHandle hook')
		else:
			raise Exception('[-] unsupported argument')


def usage(imm):
	imm.log("##########	Immunity Debugger java dumper ##########		")
	imm.log("!java-dumper	[options]	[hooks]							")
	imm.log("options:		-v	-H										")
	imm.log("				-v	enable verbosity						")
	imm.log("				-H	heaps scan 								")
	imm.log("hooks:			-c -r -C									")
	imm.log("				-c checks CreateFileW calls					")
	imm.log("				-r checks ReadFile calls					")
	imm.log("				-C checks CloseHandle calls					")


def main(args): 
	imm = immlib.Debugger()
	if not args:
		usage(imm)
		return "[-] no arguments"
	else:
		try:
			opts, _ = getopt.getopt(args, "crCvH")
		except getopt.GetoptError:
			usage(imm)
			return "[-] arguments error"
	init_hooks(imm, opts)
	return "[+] done"
