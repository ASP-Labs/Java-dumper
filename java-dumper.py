import binascii 
import immlib
import struct
from immlib import LogBpHook
from time import gmtime, strftime
from libheap import *	

'''
java-dumper project (32 bit)
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


def get_size(fmt):
	return struct.calcsize(fmt)

class java_class:
	def __init__(self):
		self.body = dict()
		self.imm = None
		self.buf = None
		self.buf_copy = None
		self.size = 0
		self.cp_infos = ''
		self.fields_count = None
		self.fields = None
		self.attributes_count = None
		self.attributes = None

	def create_class_file(self):
		filename = strftime("%Y-%m-%d %H:%M:%S", gmtime()).translate(None, ':-')
		with open(filename, "wb") as file:
			file.write(self.buf_copy[:self.size])
			self.imm.log('[+] file %s has written' % filename)

	def update_buf(self, fmt):
		self.buf = self.buf[struct.calcsize(fmt):]
		self.size += struct.calcsize(fmt)

	def parse_methods(self, methods_count):
		while methods_count > 0:
			method_info = dict()
			method_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			method_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			method_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			method_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			self.parse_attributes(method_info['attributes_count'])
			methods_count -= 1

	def parse_attributes(self, attributes_count):
		while attributes_count > 0:
			attribute_info = dict()
			attribute_info['attribute_name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			attribute_info['attribute_length'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
			self.update_buf('I')
			attribute_info['info'] = self.buf[:attribute_info['attribute_length']] 
			self.buf = self.buf[attribute_info['attribute_length']:]
			self.size += attribute_info['attribute_length']
			attributes_count -= 1

	def parse_fields(self, fields_count):
		while fields_count > 0:
			field_info = dict()
			field_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			field_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			field_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.update_buf('H')
			field_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			self.attributes_count = field_info['attributes_count']
			self.update_buf('H')
			self.parse_attributes(field_info['attributes_count'])
			fields_count -= 1

	def parse_cp_info(self, constant_pool_count):
		counter = constant_pool_count - 1
		while counter > 0:
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
				self.imm.log('[*] captured broken java class')
				filename = strftime("%Y-%m-%d %H:%M:%S", gmtime()).translate(None, ':-')
				with open(filename + '_broken.class', "wb") as file:
					file.write(self.buf_copy)
				with open(filename + '_broken_class.info', "wb") as file:
					file.write(self.__str__() + "[-] Unsupported tag: %d\n" % cp_info['tag'])
				raise Exception('[-] Unsupported tag: %d\n' % cp_info['tag'])
			# update counter
			counter -= 1
			# store info
			for key, value in cp_info.items():
				self.cp_infos += key + ' : ' + str(value) + 'pool index %d' % counter + '\n'
	
	@classmethod
	def unpack(cls, imm, buf, class_addr):
		cls = cls()
		cls.buf = buf
		cls.buf_copy = buf
		cls.imm = imm
		# get magic
		cls.body['magic'] = struct.unpack('>I', cls.buf[:get_size('I')])[0]
		cls.update_buf('I')
		# get minor version
		cls.body['minor_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		# get major version
		cls.body['major_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		# get constant pool count
		cls.body['constant_pool_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		# get constant pool
		try:
			cls.parse_cp_info(cls.body['constant_pool_count'])
		except:
			raise Exception('[*] Bad java class')
		# get access flags
		cls.body['access_flags'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		# get this class
		cls.body['this_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		# get super class
		cls.body['super_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')	
		# get interfaces count
		cls.body['interfaces_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		cls.body['interfaces'] = cls.buf[:cls.body['interfaces_count'] * 2]
		cls.buf = cls.buf[cls.body['interfaces_count'] * 2:]
		cls.size += cls.body['interfaces_count'] * 2
		# get fields count
		cls.body['fields_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.parse_fields(cls.body['interfaces_count'])
		# get methods count
		cls.body['methods_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		cls.parse_methods(cls.body['methods_count'])
		# get attributes count
		cls.body['attributes_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		cls.parse_attributes(cls.body['attributes_count'])
		# creating java class
		cls.create_class_file()
		return cls

	def __str__(self):
		result = ''
		for field, value in self.body.items():
			result += field + ' : ' + hex(value) + '\n'
		result += self.cp_infos
		return result


class CloseHandle_Hooker(LogBpHook):
	def __init__(self):
		LogBpHook.__init__(self)
		self.filename = None

	def check_java_class(self, imm, buf, chunk):
		if MAGIC in buf:
			imm.log('[+] Found class in chunk at address 0x%08X' % chunk.addr)
			createWindow('Java class message', ['[+] Found class in chunk at address 0x%08X' % chunk.addr])
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
	def __init__(self):
		LogBpHook.__init__(self)
		self.filename = None

	def check_java_class(self, imm, buf, chunk):
		if MAGIC in buf:
			imm.log('[+] Found class in chunk at address 0x%08X' % chunk.addr)
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
	def __init__(self):
		LogBpHook.__init__(self)
		self.filename = None

	def get_java_class(self, imm, buf, class_addr, to_end_size):
		try:
			j_class = java_class.unpack(imm, buf, class_addr)
			imm.log('[+] java class size: %d' % j_class.size)
			imm.log('[+] Collected next java class: %s' % j_class)
		except:
			imm.log('[*] Bad java class')

	def check_java_class(self, imm, buf, chunk):
		if MAGIC in buf:
			message = '[+] Found class in chunk at address 0x%08X' % chunk.addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.flashMessage(message)
			offset = buf.find(MAGIC)
			buf = buf[offset:]
			class_addr = chunk.addr + offset
			message = '[+] Java class address: 0x%08X' % class_addr
			imm.log(message, address = 0xFFFFFFFF)
			imm.log('[*] trying to parse java class')
			self.get_java_class(imm, buf, class_addr, chunk.size - offset)
		else:
			pass

	def scan_heaps(self, imm):
		heaps = imm.getHeapsAddress()
		for heap in heaps:
			pheap = imm.getHeap(heap)
			for chunk in pheap.chunks:
				data = imm.readMemory(chunk.addr, chunk.size)
				self.check_java_class(imm, data, chunk)

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
		self.scan_heaps(imm)


def init_hooks(imm, arg):
	CreateFileW_addr = imm.getAddress("kernel32.CreateFileW")
	ReadFile_addr = imm.getAddress("kernel32.ReadFile")
	CloseHandle_addr = imm.getAddress("kernel32.CloseHandle")
	if arg == '-s':
		whook = CreateFileW_Hooker()
		whook.add("bp_on_kernel32.CreateFileW", CreateFileW_addr)
	
	if arg == '-i':
		rhook = ReadFile_Hooker()
		rhook.add("bp_on_kernel32.ReadFile", ReadFile_addr)
	
	if arg == '-f':
		chook = CloseHandle_Hooker()
		chook.add("bp_on_kernel32.CloseHandle", CloseHandle_addr)


def usage(imm):
	imm.log(10 * '#' + ' Immunity Debugger java dumper ' + 10 * '#')
	imm.log("!java-dumper [-s] [-i] [-f]               ")
	imm.log("              -s   standart scan, checks each CreateFileW call               ")
	imm.log("              -i   intensive scan, [-s] plus checks each ReadFile call       ")
	imm.log("              -f   full scan, [-s, -i] plus checks each CloseHandle call     ")


def main(args): 
	imm = immlib.Debugger()
	if not args and len(args) != 1:
		usage(imm)
		return "[-] no arguments"
	else:
		init_hooks(imm, args[0])
	return "[+] done"
