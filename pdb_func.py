import io
import math
from pathlib import Path, PureWindowsPath
from struct import unpack

class PDB:
	def __init__(self, path):
		with open(path,"rb") as fh:
			pdb_data = fh.read()
		self.fp = io.BytesIO(pdb_data)

		self.magic = self.fp.read(32)
		self.block_size = unpack("<I",self.fp.read(4))[0]
		self.free_block_map = self.fp.read(4)
		self.num_blocks = unpack("<I",self.fp.read(4))[0]
		self.num_dir_bytes = unpack("<I",self.fp.read(4))[0]
		self.reserved = self.fp.read(4)
		self.block_map_addr = unpack("<I",self.fp.read(4))[0]

		self.streams = []
		self.section_offsets = []

		self.omap_from_src = {}
		self.omap_to_src = {}
		
		self._get_stream_info()

	def _get_stream_info(self):
		# Seek to the address of the stream index
		stream_index_addr = self.block_size * self.block_map_addr
		self.fp.seek(stream_index_addr)

		stream_directory = b""
		byte_count = 0

		# Compile data from each block referenced in the stream index into a single byte stream
		for i in range(0, math.ceil(self.num_dir_bytes / self.block_size)):
			offset = unpack("<I",self.fp.read(4))[0] * self.block_size
			pos = self.fp.tell()
			self.fp.seek(offset)
			to_read = self.block_size
			if byte_count + to_read > self.num_dir_bytes:
				to_read = self.num_dir_bytes - byte_count
			stream_directory += self.fp.read(to_read)
			byte_count += to_read
			self.fp.seek(pos)

		sp = io.BytesIO(stream_directory)
		num_streams = unpack("<I",sp.read(4))[0]

		# Get the size and block count for each stream
		for i in range(num_streams):
			sp.seek((i+1) * 4)
			curr_stream = {}
			curr_stream['size'] = unpack("<I",sp.read(4))[0]
			curr_stream['block_count'] = math.ceil(curr_stream['size'] / self.block_size)
			curr_stream['blocks'] = []
			self.streams.append(curr_stream)

		# Populate the blocks array for each stream
		for i in self.streams:
			if i['size'] == 0:
				continue
			for block in range(i['block_count']):
				i['blocks'].append(unpack("<I",sp.read(4))[0])

	def read_stream(self, index):
		stream_data = b""
		byte_count = 0
		for i in self.streams[index]['blocks']:
			offset = i * self.block_size
			self.fp.seek(offset)
			to_read = self.block_size
			if to_read + byte_count > self.streams[index]['size']:
				to_read = self.streams[index]['size'] - byte_count
			stream_data += self.fp.read(to_read)
			byte_count += to_read

		return stream_data

	def parse_dbi(self):
		self.DBI_Stream = DBIStream(self.read_stream(3))
		try:
			from_src, to_src = self.DBI_Stream.parse_omap()
			from_src_data = self.read_stream(from_src)
			fh = io.BytesIO(from_src_data)
			for i in range(0, int(len(from_src_data) / 8)):
				mapping = fh.read(8)
				src = mapping[:4]
				to = mapping[4:]
				src = int.from_bytes(src, "little")
				to = int.from_bytes(to, "little")
				self.omap_from_src[src] = to

			to_src_data = self.read_stream(to_src)
			fh = io.BytesIO(to_src_data)
			for i in range(0, int(len(to_src_data) / 8)):
				mapping = fh.read(8)
				to = mapping[:4]
				src = mapping[4:]
				src = int.from_bytes(src, "little")
				to = int.from_bytes(to, "little")
				self.omap_to_src[to] = src
		except:
			# PDB does not contain the OMAP structures, should probably add code to do things here
			pass

		self._parse_section_headers()
		self.func_list = self._parse_func_symbols()

	def _parse_section_headers(self):
		section_header_data = self.read_stream(self.DBI_Stream.section_header_index)
		sp = io.BytesIO(section_header_data)
		count = 1
		while True:
			name = sp.read(8)
			if name == b"":
				break
			name = name.split(b"\x00")[0].decode("utf-8")
			virt_size = unpack("<I", sp.read(4))[0]
			virt_address = unpack("<I", sp.read(4))[0]
			raw_data = unpack("<I", sp.read(4))[0]
			raw_data_p = unpack("<I", sp.read(4))[0]
			self.section_offsets.append(virt_address)
			sp.seek(sp.tell()+16)

	def _parse_func_symbols(self):
		self.functions_by_offset = {}
		sym_stream = self.read_stream(self.DBI_Stream.ss_index)
		sp = io.BytesIO(sym_stream)
		while True:
			sym_len = sp.read(2)
			if sym_len == b'':
				break
			sym_len = unpack("<H", sym_len)[0]
			symbol = io.BytesIO(sp.read(sym_len))
			new_symbol = {}
			sym_type = unpack("<H", symbol.read(2))[0]
			if sym_type != 4366:
				continue
			flags = unpack("<I", symbol.read(4))[0]
			if flags != 2:
				continue
			offset = unpack("<I", symbol.read(4))[0]
			section = unpack("<H", symbol.read(2))[0]
			name = symbol.read(sym_len - 12).split(b"\x00")[0].decode("utf-8")
			self.functions_by_offset[offset + self.section_offsets[section - 1]] = name

class DBIStream:
	def __init__(self, stream_data):
		self.stream = io.BytesIO(stream_data)
		self.version_sig = self.stream.read(4)
		self.version_header = unpack("<I",self.stream.read(4))[0]
		self.age = unpack("<I",self.stream.read(4))[0]
		self.gs_index = unpack("<H",self.stream.read(2))[0]
		self.build_number = unpack("<H",self.stream.read(2))[0]
		self.ps_index = unpack("<H",self.stream.read(2))[0]
		self.pdb_dll_version = unpack("<H",self.stream.read(2))[0]
		self.ss_index = unpack("<H",self.stream.read(2))[0]
		self.pdb_dll_rbld = unpack("<H",self.stream.read(2))[0]
		self.mod_info_size = unpack("<i",self.stream.read(4))[0]
		self.sec_cont_size = unpack("<i",self.stream.read(4))[0]
		self.sec_map_size = unpack("<i",self.stream.read(4))[0]
		self.src_info_size = unpack("<i",self.stream.read(4))[0]
		self.type_srv_map_size = unpack("<i",self.stream.read(4))[0]
		self.MFC_type_srv_index = unpack("<I",self.stream.read(4))[0]
		self.opt_dbg_header_size = unpack("<i",self.stream.read(4))[0]
		self.ec_sub_size = unpack("<i",self.stream.read(4))[0]
		self.flags = unpack("<H",self.stream.read(2))[0]
		self.machine = unpack("<H",self.stream.read(2))[0]
		self.padding = unpack("<I",self.stream.read(4))[0]

		self.omap_from_src = {}
		self.omap_to_src = {}

	def parse_omap(self):
		omap_to_src_offset = 64 + self.mod_info_size + self.sec_cont_size + self.sec_map_size + self.src_info_size + self.type_srv_map_size + self.ec_sub_size + 6
		self.stream.seek(omap_to_src_offset)
		omap_to_src_index = unpack("<H",self.stream.read(2))[0]
		omap_from_src_index = unpack("<H",self.stream.read(2))[0]
		self.section_header_index = unpack("<H",self.stream.read(2))[0]
		return (omap_from_src_index, omap_to_src_index)