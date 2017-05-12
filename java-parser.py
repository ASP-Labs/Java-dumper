import sys
import binascii 
import struct
from time import gmtime, strftime

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

verbose = True

def get_size(fmt):
	return struct.calcsize(fmt)

class java_class:
	def __init__(self):
		self.body = dict()
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

	def update_buf(self, fmt):
		self.buf = self.buf[struct.calcsize(fmt):]
		self.size += struct.calcsize(fmt)

	def parse_methods(self, methods_count):
		while methods_count > 0:
			method_info = dict()
			method_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("method access flags: 0x%04X" % method_info['access_flags'])
			self.update_buf('H')
			method_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("method name index: 0x%04X" % method_info['name_index'])
			self.update_buf('H')
			method_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("method descriptor index: 0x%04X" % method_info['descriptor_index'])
			self.update_buf('H')
			method_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("method attributes count: 0x%04X" % method_info['attributes_count'])
			self.update_buf('H')
			self.parse_attributes(method_info['attributes_count'])
			methods_count -= 1

	def parse_attributes(self, attributes_count):
		while attributes_count > 0:
			attribute_info = dict()
			attribute_info['attribute_name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("attribute name index: 0x%04X" % attribute_info['attribute_name_index'])
			self.update_buf('H')
			attribute_info['attribute_length'] = struct.unpack('>I', self.buf[:get_size('I')])[0]
			print("attribute length: 0x%08X" % attribute_info['attribute_length'])
			self.update_buf('I')
			attribute_info['info'] = self.buf[:attribute_info['attribute_length']] 
			print("info: %s" % " ".join("%02X" % ord(el) for el in (attribute_info['info'])))
			self.buf = self.buf[attribute_info['attribute_length']:]
			self.size += attribute_info['attribute_length']
			attributes_count -= 1

	def parse_fields(self, fields_count):
		while fields_count > 0:
			field_info = dict()
			field_info['access_flags'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("access flags: 0x%04X" % field_info['access_flags'])
			self.update_buf('H')
			field_info['name_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("name index: 0x%04X" % field_info['name_index'])
			self.update_buf('H')
			field_info['descriptor_index'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("descriptor index: 0x%04X" % field_info['descriptor_index'])
			self.update_buf('H')
			field_info['attributes_count'] = struct.unpack('>H', self.buf[:get_size('H')])[0]
			print("attributes count: 0x%04X" % field_info['attributes_count'])
			self.update_buf('H')
			self.parse_attributes(field_info['attributes_count'])
			fields_count -= 1

	def parse_cp_info(self, constant_pool_count):
		counter = constant_pool_count - 1
		while counter > 0:
			print('[*] Counter = %d' % counter)
			print('-'*10)
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
					print(key + ' : ' + str(value))
			print('-'*10)

	@classmethod
	def unpack(cls, buf):
		cls = cls()
		cls.buf = buf
		cls.buf_copy = buf
		# get magic
		if verbose:
			print('[*] unpacking magic')
		cls.body['magic'] = struct.unpack('>I', cls.buf[:get_size('I')])[0]
		cls.update_buf('I')
		print("magic: 0x%04X" % cls.body['magic'])
		# get minor version
		if verbose:
			print('[*] unpacking minor version')
		cls.body['minor_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("minor version: 0x%04X" % cls.body['minor_version'])
		# get major version
		if verbose:
			print('[*] unpacking major version')
		cls.body['major_version'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("major version: 0x%04X" % cls.body['major_version'])
		# get constant pool count
		if verbose:
			print('[*] unpacking constant pool count')
		cls.body['constant_pool_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("constant pool count: 0x%04X" % cls.body['constant_pool_count'])
		# get constant pool
		if verbose:
			print('[*] unpacking constant pool')
		cls.parse_cp_info(cls.body['constant_pool_count'])
		# get access flags
		if verbose:
			print('[*] unpacking access flags')
		cls.body['access_flags'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("access flags: 0x%04X" % cls.body['access_flags'])
		# get this class
		if verbose:
			print('[*] unpacking this class')
		cls.body['this_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("this class: 0x%04X" % cls.body['this_class'])
		# get super class
		if verbose:
			print('[*] unpacking super class')
		cls.body['super_class'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')	
		print("super class: 0x%04X" % cls.body['super_class'])
		# get interfaces count
		if verbose:
			print('[*] unpacking interfaces count')
		cls.body['interfaces_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("interfaces count: 0x%04X" % cls.body['interfaces_count'])
		if verbose:
			print('[*] unpacking interfaces')
		cls.body['interfaces'] = cls.buf[:cls.body['interfaces_count'] * 2]
		cls.buf = cls.buf[cls.body['interfaces_count'] * 2:]
		cls.size += cls.body['interfaces_count'] * 2
		print("interfaces: %s" % " ".join("%02X" % ord(el) for el in cls.body['interfaces']))
		# get fields count
		if verbose:
			print('[*] unpacking fields count')
		cls.body['fields_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		print("fields count: 0x%04X" % cls.body['fields_count'])
		cls.update_buf('H')
		# get fields
		cls.parse_fields(cls.body['fields_count'])
		# get methods count
		if verbose:
			print('[*] unpacking methods count')
		cls.body['methods_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("methods count: 0x%04X" % cls.body['methods_count'])
		# get methods
		cls.parse_methods(cls.body['methods_count'])
		# get attributes count
		if verbose:
			print('[*] unpacking attributes count')
		cls.body['attributes_count'] = struct.unpack('>H', cls.buf[:get_size('H')])[0]
		cls.update_buf('H')
		print("attributes count: 0x%04X" % cls.body['attributes_count'])
		# get attributes
		cls.parse_attributes(cls.body['attributes_count'])
		# creating java class
		cls.create_class_file()
		print('[+] Class file has written')
		return cls

	def __str__(self):
		result = ''
		for field, value in self.body.items():
			result += field + ' : ' + hex(value) + '\n'
		result += self.cp_infos
		return result

if __name__ == '__main__':
	try:
		filename = sys.argv[1]
	except:
		print('[-] Input filename is empty')
		sys.exit(1)
	# get data
	with open(filename, 'rb') as file:
		data = file.read()
	# unpack java class
	j_class = java_class.unpack(data)