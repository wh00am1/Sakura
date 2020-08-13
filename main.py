#!/usr/bin/env python2

import os, sys
from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import *
from pwn import *


title = \
"""
= =====  ========= = ===== ==== ======== ==== =========== ===== =========

     _______.     ___       __  ___  __    __  .______          ___      
    /       |    /   \     |  |/  / |  |  |  | |   _  \        /   \     
   |   (----`   /  ^  \    |  '  /  |  |  |  | |  |_)  |      /  ^  \    
    \   \      /  /_\  \   |    <   |  |  |  | |      /      /  /_\  \   
.----)   |    /  _____  \  |  .  \  |  `--'  | |  |\  \----./  _____  \  
|_______/    /__/     \__\ |__|\__\  \______/  | _| `._____/__/     \__\ 


------------------ Binary Analysis Tool by wh00am1 ----------------------

=========================================================================


"""

usage = \
"""
list/ show:
	
	-list sections / functions

disassemble:

	-disassemble section/ function/ address by N bytes
	
	usage:
		disassemble/disass/disas [funcion name/ section name/ hexed adddress] 
	
	ex.
		disassemble .text
		disass main
		disas 0x400636  

"""

def perror(msg):
	print '\t[-] Error {}'.format(msg)
	exit(1)

def CheckElfExist(name, path):
	if os.path.exists(path):
		#print '[+] File : {} exists!'.format(name)
		pass
	else:
		print '\t[-] File : {} not found at {}'.format(name, path)
		sys.exit(1)

def CheckElf(file, path):
	CheckElfExist(file, path)
	try:
		e = ELFFile(open(path, 'rb'))
		print '\t[+] Binary Arch : {}'.format(e.header.e_machine.split('_')[1])
	except ELFError:
		perror('{} not a valid ELF file'.format(file))
def checksec(file):
	file = ELF(file)
	return 0
def parsesections(e):
	print '\n\t[+] Analysing sections of this file:'
	for section in e.iter_sections():
		print '\t{}\t{}'.format(hex(section['sh_addr']), section.name)
	return 0

def parserelocations(e):
	print '\n\t[+] Analysing RelocationSection '
	for section in e.iter_sections():
		if isinstance(section, RelocationSection):
			print '\n\t{}:'.format(section)
			symbol_table = e.get_section(section['sh_link'])
			for relocation in section.iter_relocations():
				symbol = symbol_table.get_symbol(relocation['r_info_sym'])
				addr = hex(relocation['r_offset'])
				print '\t{}\t\tsym.{}'.format(addr, symbol.name)
	return 0
opcodes = ''
def disass(e, target, mode):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	if mode == 1: #disass section
		code = e.get_section_by_name(target)
		opcodes = code.data()
		address = code['sh_addr']
		print '\n\t[+] Disassembly of section {}\n'.format(target)
		for i in md.disasm(opcodes, address):
			print '\t\t0x{}:\t{}\t{}'.format(i.address, i.mnemonic, i.op_str)
		return 0
	elif mode == 2:
		target = target[:-1]
		r = ELF(e)
		target_entry = r.symbols[target]
		e = ELFFile(open(e, 'rb'))
		code = e.get_section_by_name('.text')
		opcodes = code.data()
		address = code['sh_addr']
		print '\n\t[+] Disassembly of function {}\n'.format(target)
		for i in md.disasm(opcodes, address):
			if i.address >= target_entry:
				if 'ret' in i.mnemonic:
					print '\t\t0x{}:\t{}\t{}'.format(i.address, i.mnemonic, i.op_str)
					return 0
				print '\t\t0x{}:\t{}\t{}'.format(i.address, i.mnemonic, i.op_str)
		return 0 
	elif mode == 3:
		target = int(target, 16)
		n = raw_input('how many bytes to disassemble:')
		code = e.get_section_by_name('.text')
		opcodes = code.data()
		address = code['sh_addr']
		print '\n\t[+] Disassembly of address {}\n'.format(hex(target))
		for i in md.disasm(opcodes, address):
			if int(str(i.address), 16) >= target:
					print '\t\t0x{}:\t{}\t{}'.format(i.address, i.mnemonic, i.op_str)
			if int(str(i.address), 16) > int(target +int(n)):
				return 0
	else:
		perror('unknown {} , {} or {}'.format(e, target, mode))
		return 1

def main():
	print title
	if len(sys.argv) != 2:
		print usage
		exit(1)
	fpath, fname = sys.argv[1], sys.argv[1].split('/')[-1]
	CheckElf(fname, fpath)
	f = open(fpath, 'rb')
	e = ELFFile(open(fpath, 'rb'))
	while(True):
		c = raw_input('\nSakura>').split(' ')
		print '[+] Your Command : {} {}'.format(c[0], c[1])
		if c[0] == 'list' or c[0] == 'show':
			w = c[1].replace('\n', '')
			if w == 'sections' or w == 'secs':
				parsesections(e)
				continue
			if w == 'relocations' or w == 'relo' or w == 'plt':
				parserelocations(e)
				continue
			else:
				print('invalid argument: {}'.format(w))
				continue

		elif c[0] == 'disassemble' or c[0] == 'disass' or c[0] == 'disas':
			if c[1].startswith('.'):
				disass(e, c[1], 1)
			if c[1].startswith('0x'):
				disass(e, c[1], 3)
			else:
				disass(fpath, c[1], 2)
		elif c[0].replace('\n', '') == 'checksec':
			checksec(fpath)
		elif c[0].replace('\n', '') == 'help':
			print title
			print usage
		else:
			print '[-] Command : {} {} not found'.format(c[0], c[1])
			print 'Usage:'
			print usage

if __name__ == '__main__':
	main()