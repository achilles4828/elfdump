import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type
from capstone import *
#from __future__ import print_function
sys.path[0:0] =['.','..']
def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
    	elffile = ELFFile(f)
    	code_section = '.text'
    	for section in elffile.iter_sections():
        	print (section.name)
        print("__________________________________end__________________________________")
        for section in elffile.iter_sections():
            if section.name.startswith('.debug'):
                print('  ' + section.name)
            else:
                print("No debug sections available")
                break     
                
        print("__________________________________end__________________________________")
        for section in elffile.iter_sections():
            print hex(section['sh_addr']), section.name, section['sh_size']
        print("__________________________________end__________________________________")
        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        addr = code['sh_addr']
        print 'Entry Point:', hex(elffile.header['e_entry'])
        print("__________________________________end__________________________________")
        print "<<.TEXT Disassembly>>"
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(opcodes, addr):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print("__________________________________end__________________________________")
        code = elffile.get_section_by_name('.got.plt')
        opcodes = code.data()
        addr = code['sh_addr']
        print "<<.GOT.PLT Disassembly>>"
        #print 'Entry Point:', hex(elffile.header['e_entry'])
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(opcodes, addr):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print("__________________________________end__________________________________")
        code = elffile.get_section_by_name('.plt')
        opcodes = code.data()
        addr = code['sh_addr']
        print "<<.PLT Disassembly>>"
        #print 'Entry Point:', hex(elffile.header['e_entry'])
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(opcodes, addr):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print("__________________________________end__________________________________")
        for section in elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symtable = elffile.get_section(section['sh_link'])
            print('  %s section with %s relocations' % (section.name, section.num_relocations()))
            for reloc in section.iter_relocations():
                symbol = symtable.get_symbol(reloc['r_info_sym'])
                print '    Relocation (%s)' % 'RELA' if reloc.is_RELA() else 'REL'
                print '      offset = %s' % hex(reloc['r_offset'])
                print symbol.name, 'type:', describe_reloc_type(reloc['r_info_type'], elffile), 'load at: ', hex(reloc['r_offset'])    
if __name__ == '__main__':
    if len(sys.argv) == 2:
        process_file(sys.argv[1])   