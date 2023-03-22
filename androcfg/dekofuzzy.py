"""
####
# This is a fork of Dexofuzzy core functions that we need for AndroCFG. 
#### 
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""

import ctypes
import struct
import ssdeep


def hash(dex_data):
    """
    This function compute the dexofuzzy of a dex binary data.
    :param dex_data: bytes
    :return: The dexofuzzy of the dex binary data
    """

    if not isinstance(dex_data, bytes):
        raise TypeError("must be of bytes type")

    generate_dexoFuzzy = ExtractOpcode()
    generate_dexoFuzzy.dex = dex_data
    generate_dexoFuzzy.get_bytecode(0, len(dex_data))
    feature = ""
    for opcodes in generate_dexoFuzzy.opcodes_in_method:
        feature += ssdeep.hash(opcodes, encoding="UTF-8").split(":")[1]

        dexofuzzy = ssdeep.hash(feature, encoding="UTF-8")

    return dexofuzzy


class ExtractOpcode:
    """
    This class extracts the opcode from the dex file.
    """
    def __init__(self):
        self.dex = None
        self.header = {}
        self.string_ids = []
        self.type_ids = []
        self.class_defs = []
        self.opcodes_in_method = []

    def get_opcodes(self, dex_data: bytes) -> list:
        """
        This function extracts the opcode from the dex file.
        :param dex_data: bytes
        :return: The opcode list of the dex file.
        """
        self.opcodes_in_method = []
        dex_magic_numbers = [b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
                             b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00"]

        if isinstance(dex_data, bytes):
            self.dex = dex_data
            self.__get_header()
            self.__get_string_ids()
            self.__get_type_ids()
            self.__get_class_defs()
            self.__dex_to_smali()

        return self.opcodes_in_method

    def __get_header(self):
        header = {}
        header["magic_number"] = self.dex[0x00:0x08]
        header["checksum"] = struct.unpack("<L", self.dex[0x08:0x0C])[0]
        header["sha1"] = self.dex[0x0C:0x20]
        header["file_size"] = struct.unpack("<L", self.dex[0x20:0x24])[0]
        header["header_size"] = struct.unpack("<L", self.dex[0x24:0x28])[0]
        header["endian_tag"] = struct.unpack("<L", self.dex[0x28:0x2C])[0]
        header["link_size"] = struct.unpack("<L", self.dex[0x2C:0x30])[0]
        header["link_off"] = struct.unpack("<L", self.dex[0x30:0x34])[0]
        header["map_off"] = struct.unpack("<L", self.dex[0x34:0x38])[0]
        header["string_ids_size"] = struct.unpack("<L", self.dex[0x38:0x3C])[0]
        header["string_ids_off"] = struct.unpack("<L", self.dex[0x3C:0x40])[0]
        header["type_ids_size"] = struct.unpack("<L", self.dex[0x40:0x44])[0]
        header["type_ids_off"] = struct.unpack("<L", self.dex[0x44:0x48])[0]
        header["proto_ids_size"] = struct.unpack("<L", self.dex[0x48:0x4C])[0]
        header["proto_ids_off"] = struct.unpack("<L", self.dex[0x4C:0x50])[0]
        header["field_ids_size"] = struct.unpack("<L", self.dex[0x50:0x54])[0]
        header["field_ids_off"] = struct.unpack("<L", self.dex[0x54:0x58])[0]
        header["method_ids_size"] = struct.unpack("<L", self.dex[0x58:0x5C])[0]
        header["method_ids_off"] = struct.unpack("<L", self.dex[0x5C:0x60])[0]
        header["class_defs_size"] = struct.unpack("<L", self.dex[0x60:0x64])[0]
        header["class_defs_off"] = struct.unpack("<L", self.dex[0x64:0x68])[0]
        header["data_size"] = struct.unpack("<L", self.dex[0x68:0x6C])[0]
        header["data_off"] = struct.unpack("<L", self.dex[0x6C:0x70])[0]

        self.header = header

    def __get_string_ids(self):
        string_ids = []
        string_ids_size = self.header["string_ids_size"]
        string_ids_off = self.header["string_ids_off"]

        for i in range(string_ids_size):
            offset = struct.unpack("<L", self.dex[string_ids_off+(i*4):
                                                  string_ids_off+(i*4)+4])[0]
            utf16_size, _ = self.__decode_uleb128(offset)

            if utf16_size <= 0:
                string_id = ""

            else:
                utf16_off = self.__get_utf16_off(utf16_size)
                string_id = self.dex[offset+utf16_off:
                                     offset+utf16_off+utf16_size]

            string_ids.append(string_id)

        self.string_ids = string_ids

    def __get_type_ids(self):
        type_ids = []
        type_ids_size = self.header["type_ids_size"]
        type_ids_off = self.header["type_ids_off"]

        for i in range(type_ids_size):
            descriptor_idx = struct.unpack("<L", self.dex[
                                                    type_ids_off+(i*4):
                                                    type_ids_off+(i*4)+4])[0]
            type_ids.append(descriptor_idx)

        self.type_ids = type_ids

    def __get_class_defs(self):
        class_defs = []
        class_defs_size = self.header["class_defs_size"]
        class_defs_off = self.header["class_defs_off"]

        for i in range(class_defs_size):
            class_def = {}
            class_def["class_idx"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20):
                                                class_defs_off+(i*0x20)+4])[0]
            class_def["access_flags"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+4:
                                                class_defs_off+(i*0x20)+8])[0]
            class_def["superclass_idx"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+8:
                                                class_defs_off+(i*0x20)+12])[0]
            class_def["interfaces_off"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+12:
                                                class_defs_off+(i*0x20)+16])[0]
            class_def["source_file_idx"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+16:
                                                class_defs_off+(i*0x20)+20])[0]
            class_def["annotations_off"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+20:
                                                class_defs_off+(i*0x20)+24])[0]
            class_def["class_data_off"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+24:
                                                class_defs_off+(i*0x20)+28])[0]
            class_def["static_values_off"] = struct.unpack("<L", self.dex[
                                                class_defs_off+(i*0x20)+28:
                                                class_defs_off+(i*0x20)+32])[0]
            class_defs.append(class_def)

        self.class_defs = class_defs

    def __dex_to_smali(self):
        class_defs_size = self.header["class_defs_size"]

        for i in range(class_defs_size):
            class_str = self.string_ids[self.type_ids[
                                        self.class_defs[i]["class_idx"]]]
            if class_str.find(b"Landroid/support/") == -1:
                if self.class_defs[i]["class_data_off"] > 0:
                    self.__get_class_data_item(i)

    def __get_class_data_item(self, idx):
        offset = self.class_defs[idx]["class_data_off"]
        static_fields, static_fields_size = self.__decode_uleb128(offset)
        offset += static_fields_size
        instance_fields, instance_fields_size = self.__decode_uleb128(offset)
        offset += instance_fields_size
        direct_methods, direct_methods_size = self.__decode_uleb128(offset)
        offset += direct_methods_size
        virtual_methods, virtual_methods_size = self.__decode_uleb128(offset)
        offset += virtual_methods_size

        if static_fields > 0:
            offset = self.__decode_field(offset, static_fields)
        if instance_fields > 0:
            offset = self.__decode_field(offset, instance_fields)
        if direct_methods > 0:
            offset = self.__decode_method(offset, direct_methods)
        if virtual_methods > 0:
            offset = self.__decode_method(offset, virtual_methods)

    def __decode_field(self, offset, fields):
        for _ in range(fields):
            _, size = self.__decode_uleb128(offset)
            offset += size
            _, size = self.__decode_uleb128(offset)
            offset += size

        return offset

    def __decode_method(self, offset, methods):
        for _ in range(methods):
            _, size = self.__decode_uleb128(offset)
            offset += size
            _, size = self.__decode_uleb128(offset)
            offset += size
            code_off, size = self.__decode_uleb128(offset)
            offset += size

            if code_off != 0:
                current_off = code_off
                code_items = self.__get_code_item(current_off)
                current_off += 16
                bytecode_size = ctypes.c_ushort(code_items["insns_size"]*2).value
                bytecode_off = current_off
                self.get_bytecode(bytecode_off, bytecode_size)

        return offset

    def __get_code_item(self, offset):
        registers_size = struct.unpack("<H", self.dex[offset:offset+2])[0]
        ins_size = struct.unpack("<H", self.dex[offset+2:offset+4])[0]
        outs_size = struct.unpack("<H", self.dex[offset+4:offset+6])[0]
        tries_size = struct.unpack("<H", self.dex[offset+6:offset+8])[0]
        debug_info_off = struct.unpack("<L", self.dex[offset+8:offset+12])[0]
        insns_size = struct.unpack("<L", self.dex[offset+12:offset+16])[0]

        code_items = {}
        code_items["registers_size"] = registers_size
        code_items["ins_size"] = ins_size
        code_items["outs_size"] = outs_size
        code_items["tries_size"] = tries_size
        code_items["debug_info_off"] = debug_info_off
        code_items["insns_size"] = insns_size

        return code_items

    def get_bytecode(self, offset, bytecode_size):
        # try:
        bytecode = [0]*bytecode_size
        for i in range(0, bytecode_size):
            bytecode[i] = self.dex[offset+i]

        opcode_off_format = {
            0x00: self.__format_10x, 0x01: self.__format_12x,
            0x02: self.__format_22x, 0x03: self.__format_32x,
            0x04: self.__format_12x, 0x05: self.__format_22x,
            0x06: self.__format_32x, 0x07: self.__format_12x,
            0x08: self.__format_22x, 0x09: self.__format_32x,
            0x0a: self.__format_11x, 0x0b: self.__format_11x,
            0x0c: self.__format_11x, 0x0d: self.__format_11x,
            0x0e: self.__format_10x, 0x0f: self.__format_11x,
            0x10: self.__format_11x, 0x11: self.__format_11x,
            0x12: self.__format_11n, 0x13: self.__format_21s,
            0x14: self.__format_31i, 0x15: self.__format_21h,
            0x16: self.__format_21s, 0x17: self.__format_31i,
            0x18: self.__format_51l, 0x19: self.__format_21h,
            0x1a: self.__format_21c, 0x1b: self.__format_31c,
            0x1c: self.__format_21c, 0x1d: self.__format_11x,
            0x1e: self.__format_11x, 0x1f: self.__format_21c,
            0x20: self.__format_22c, 0x21: self.__format_12x,
            0x22: self.__format_21c, 0x23: self.__format_22c,
            0x24: self.__format_35c, 0x25: self.__format_3rc,
            0x26: self.__format_31t, 0x27: self.__format_11x,
            0x28: self.__format_10t, 0x29: self.__format_20t,
            0x2a: self.__format_30t, 0x2b: self.__format_31t,
            0x2c: self.__format_31t, 0x2d: self.__format_23x,
            0x2e: self.__format_23x, 0x2f: self.__format_23x,
            0x30: self.__format_23x, 0x31: self.__format_23x,
            0x32: self.__format_22t, 0x33: self.__format_22t,
            0x34: self.__format_22t, 0x35: self.__format_22t,
            0x36: self.__format_22t, 0x37: self.__format_22t,
            0x38: self.__format_21t, 0x39: self.__format_21t,
            0x3a: self.__format_21t, 0x3b: self.__format_21t,
            0x3c: self.__format_21t, 0x3d: self.__format_21t,
            0x3e: self.__format_10x, 0x3f: self.__format_10x,
            0x40: self.__format_10x, 0x41: self.__format_10x,
            0x42: self.__format_10x, 0x43: self.__format_10x,
            0x44: self.__format_23x, 0x45: self.__format_23x,
            0x46: self.__format_23x, 0x47: self.__format_23x,
            0x48: self.__format_23x, 0x49: self.__format_23x,
            0x4a: self.__format_23x, 0x4b: self.__format_23x,
            0x4c: self.__format_23x, 0x4d: self.__format_23x,
            0x4e: self.__format_23x, 0x4f: self.__format_23x,
            0x50: self.__format_23x, 0x51: self.__format_23x,
            0x52: self.__format_22c, 0x53: self.__format_22c,
            0x54: self.__format_22c, 0x55: self.__format_22c,
            0x56: self.__format_22c, 0x57: self.__format_22c,
            0x58: self.__format_22c, 0x59: self.__format_22c,
            0x5a: self.__format_22c, 0x5b: self.__format_22c,
            0x5c: self.__format_22c, 0x5d: self.__format_22c,
            0x5e: self.__format_22c, 0x5f: self.__format_22c,
            0x60: self.__format_21c, 0x61: self.__format_21c,
            0x62: self.__format_21c, 0x63: self.__format_21c,
            0x64: self.__format_21c, 0x65: self.__format_21c,
            0x66: self.__format_21c, 0x67: self.__format_21c,
            0x68: self.__format_21c, 0x69: self.__format_21c,
            0x6a: self.__format_21c, 0x6b: self.__format_21c,
            0x6c: self.__format_21c, 0x6d: self.__format_21c,
            0x6e: self.__format_35c, 0x6f: self.__format_35c,
            0x70: self.__format_35c, 0x71: self.__format_35c,
            0x72: self.__format_35c, 0x73: self.__format_10x,
            0x74: self.__format_3rc, 0x75: self.__format_3rc,
            0x76: self.__format_3rc, 0x77: self.__format_3rc,
            0x78: self.__format_3rc, 0x79: self.__format_10x,
            0x7a: self.__format_10x, 0x7b: self.__format_12x,
            0x7c: self.__format_12x, 0x7d: self.__format_12x,
            0x7e: self.__format_12x, 0x7f: self.__format_12x,
            0x80: self.__format_12x, 0x81: self.__format_12x,
            0x82: self.__format_12x, 0x83: self.__format_12x,
            0x84: self.__format_12x, 0x85: self.__format_12x,
            0x86: self.__format_12x, 0x87: self.__format_12x,
            0x88: self.__format_12x, 0x89: self.__format_12x,
            0x8a: self.__format_12x, 0x8b: self.__format_12x,
            0x8c: self.__format_12x, 0x8d: self.__format_12x,
            0x8e: self.__format_12x, 0x8f: self.__format_12x,
            0x90: self.__format_23x, 0x91: self.__format_23x,
            0x92: self.__format_23x, 0x93: self.__format_23x,
            0x94: self.__format_23x, 0x95: self.__format_23x,
            0x96: self.__format_23x, 0x97: self.__format_23x,
            0x98: self.__format_23x, 0x99: self.__format_23x,
            0x9a: self.__format_23x, 0x9b: self.__format_23x,
            0x9c: self.__format_23x, 0x9d: self.__format_23x,
            0x9e: self.__format_23x, 0x9f: self.__format_23x,
            0xa0: self.__format_23x, 0xa1: self.__format_23x,
            0xa2: self.__format_23x, 0xa3: self.__format_23x,
            0xa4: self.__format_23x, 0xa5: self.__format_23x,
            0xa6: self.__format_23x, 0xa7: self.__format_23x,
            0xa8: self.__format_23x, 0xa9: self.__format_23x,
            0xaa: self.__format_23x, 0xab: self.__format_23x,
            0xac: self.__format_23x, 0xad: self.__format_23x,
            0xae: self.__format_23x, 0xaf: self.__format_23x,
            0xb0: self.__format_12x, 0xb1: self.__format_12x,
            0xb2: self.__format_12x, 0xb3: self.__format_12x,
            0xb4: self.__format_12x, 0xb5: self.__format_12x,
            0xb6: self.__format_12x, 0xb7: self.__format_12x,
            0xb8: self.__format_12x, 0xb9: self.__format_12x,
            0xba: self.__format_12x, 0xbb: self.__format_12x,
            0xbc: self.__format_12x, 0xbd: self.__format_12x,
            0xbe: self.__format_12x, 0xbf: self.__format_12x,
            0xc0: self.__format_12x, 0xc1: self.__format_12x,
            0xc2: self.__format_12x, 0xc3: self.__format_12x,
            0xc4: self.__format_12x, 0xc5: self.__format_12x,
            0xc6: self.__format_12x, 0xc7: self.__format_12x,
            0xc8: self.__format_12x, 0xc9: self.__format_12x,
            0xca: self.__format_12x, 0xcb: self.__format_12x,
            0xcc: self.__format_12x, 0xcd: self.__format_12x,
            0xce: self.__format_12x, 0xcf: self.__format_12x,
            0xd0: self.__format_22s, 0xd1: self.__format_22s,
            0xd2: self.__format_22s, 0xd3: self.__format_22s,
            0xd4: self.__format_22s, 0xd5: self.__format_22s,
            0xd6: self.__format_22s, 0xd7: self.__format_22s,
            0xd8: self.__format_22b, 0xd9: self.__format_22b,
            0xda: self.__format_22b, 0xdb: self.__format_22b,
            0xdc: self.__format_22b, 0xdd: self.__format_22b,
            0xde: self.__format_22b, 0xdf: self.__format_22b,
            0xe0: self.__format_22b, 0xe1: self.__format_22b,
            0xe2: self.__format_22b, 0xe3: self.__format_10x,
            0xe4: self.__format_10x, 0xe5: self.__format_10x,
            0xe6: self.__format_10x, 0xe7: self.__format_10x,
            0xe8: self.__format_10x, 0xe9: self.__format_10x,
            0xea: self.__format_10x, 0xeb: self.__format_10x,
            0xec: self.__format_10x, 0xed: self.__format_10x,
            0xee: self.__format_10x, 0xef: self.__format_10x,
            0xf0: self.__format_10x, 0xf1: self.__format_10x,
            0xf2: self.__format_10x, 0xf3: self.__format_10x,
            0xf4: self.__format_10x, 0xf5: self.__format_10x,
            0xf6: self.__format_10x, 0xf7: self.__format_10x,
            0xf8: self.__format_10x, 0xf9: self.__format_10x,
            0xfa: self.__format_45cc, 0xfb: self.__format_4rcc,
            0xfc: self.__format_35c, 0xfd: self.__format_3rc,
            0xfe: self.__format_21c, 0xff: self.__format_21c,
        }

        opcodes = ""
        current_off = 0
        while bytecode_size > current_off:
            opcode_hex = bytecode[current_off]

            if opcode_hex in opcode_off_format:
                opcodes += f"{opcode_hex:02x}"
                current_off = opcode_off_format[opcode_hex](
                                                bytecode, current_off)
            else:
                current_off += 1
                break

        self.opcodes_in_method.append(opcodes)

    # except Exception:
        self.opcodes_in_method.append(opcodes)

    def __format_10x(self, bytecode, offset):
        try:
            offset += 1
            if bytecode[offset] == 0x00:
                offset += 1

            elif bytecode[offset] == 0x01:
                offset = self.__format_31t_packed_switch_payload(bytecode, offset)

            elif bytecode[offset] == 0x02:
                offset = self.__format_31t_sparse_switch_payload(bytecode, offset)

            elif bytecode[offset] == 0x03:
                offset = self.__format_31t_fill_array_data_payload(bytecode, offset)

            else:
                offset += 1

            return offset

        except Exception:
            return offset

    def __format_10t(self, _, offset):
        offset += 2
        return offset

    def __format_11n(self, _, offset):
        offset += 2
        return offset

    def __format_11x(self, _, offset):
        offset += 2
        return offset

    def __format_12x(self, _, offset):
        offset += 2
        return offset

    def __format_20t(self, _, offset):
        offset += 4
        return offset

    def __format_21c(self, _, offset):
        offset += 4
        return offset

    def __format_21h(self, _, offset):
        offset += 4
        return offset

    def __format_21s(self, _, offset):
        offset += 4
        return offset

    def __format_21t(self, _, offset):
        offset += 4
        return offset

    def __format_22b(self, _, offset):
        offset += 4
        return offset

    def __format_22c(self, _, offset):
        offset += 4
        return offset

    def __format_22s(self, _, offset):
        offset += 4
        return offset

    def __format_22t(self, _, offset):
        offset += 4
        return offset

    def __format_22x(self, _, offset):
        offset += 4
        return offset

    def __format_23x(self, _, offset):
        offset += 4
        return offset

    def __format_30t(self, _, offset):
        offset += 6
        return offset

    def __format_31c(self, _, offset):
        offset += 6
        return offset

    def __format_31i(self, _, offset):
        offset += 6
        return offset

    def __format_31t(self, _, offset):
        offset += 6
        return offset

    def __format_31t_packed_switch_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        size = shift | bytecode[offset+1]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        off_check = (offset-2)+(int((size*2)+4)*2)
        offset += 6

        offset += (4*size)

        if offset != off_check:
            return off_check

        return offset

    def __format_31t_sparse_switch_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        size = shift | bytecode[offset+1]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        off_check = (offset-2)+(int((size*4)+2)*2)
        offset += 2

        offset += (4*size)
        offset += (4*size)

        if offset != off_check:
            return off_check

        return offset

    def __format_31t_fill_array_data_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        offset += 1
        element_width = shift | bytecode[offset]
        element_width = struct.unpack("<H", struct.pack(">H", element_width))[0]
        offset += 1
        shift = bytecode[offset] << 8
        offset += 1
        size = shift | bytecode[offset]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        offset += 1
        off_check = (offset-6)+(int((size*element_width+1)/2+4)*2)
        offset += 2

        offset += (1*size*element_width)

        if offset != off_check:
            return off_check

        return offset

    def __format_32x(self, _, offset):
        offset += 6
        return offset

    def __format_35c(self, _, offset):
        offset += 6
        return offset

    def __format_3rc(self, _, offset):
        offset += 6
        return offset

    def __format_51l(self, _, offset):
        offset += 10
        return offset

    def __format_4rcc(self, _, offset):
        offset += 8
        return offset

    def __format_45cc(self, _, offset):
        offset += 12
        return offset

    def __decode_uleb128(self, offset):
        result = shift = size = 0

        while True:
            byte = self.dex[offset+size]
            result |= (byte & 0x7f) << shift
            size += 1

            if (byte & 0x80) == 0:
                break

            shift += 7

        return result, size

    def __get_utf16_off(self, utf16_size):
        if utf16_size < (0x80):
            return 1

        if utf16_size < (0x80 << 7):
            return 2

        if utf16_size < (0x80 << 14):
            return 3

        return 4
