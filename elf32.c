/* MSPDebug - debugging tool for the eZ430
 * Copyright (C) 2009, 2010 Daniel Beer
 *
 * Big Endian support contributed by Steven Bytnar
 * Copyright (C) 2011, Steven Bytnar
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libelf.h>
#else
#include <elf.h>
#endif
#include <gelf.h>
#include "elf32.h"
#include "output.h"

#ifndef EM_MSP430
#define EM_MSP430	0x0069
#endif

static const uint8_t elf32_id[] = {
	ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS32
};

#define MAX_PHDRS	32
#define MAX_SHDRS	128

struct elf32_info {
	Elf			*elf;
	GElf_Ehdr               file_ehdr;
	GElf_Phdr               file_phdrs[MAX_PHDRS];
	GElf_Shdr               file_shdrs[MAX_SHDRS];

	Elf_Data		*string_data;
};

static int read_ehdr(struct elf32_info *info, FILE *in)
{
	/* Read and check the ELF header */
	char *id;

	rewind(in);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printc_err("elf32: elf_version failed");
		return -1;
	}

	/* ELF_C_READ_MMAP* is not available in Mac OS X macports libelf @0.8.10_1 */
	info->elf = elf_begin(fileno(in), ELF_C_READ, NULL);
	if (info->elf == 0) {
		printc_err("elf32: elf_begin failed");
		return -1;
	}

	if (elf_kind(info->elf) != ELF_K_ELF) {
		printc_err("elf32: elf_kind is not ELF_K_ELF");
		return -1;
	}

	if (gelf_getehdr(info->elf, &info->file_ehdr) == 0) {
		printc_err("elf32: couldn't get ELF header");
		return -1;
	}

	if ((id = elf_getident(info->elf, NULL)) == 0) {
		printc_err("elf32: couldn't getident");
		return -1;
	}
	if (memcmp(id, elf32_id, sizeof(elf32_id))) {
		printc_err("elf32: not an ELF32 file\n");
		return -1;
	}

	return 0;
}

static int read_phdr(struct elf32_info *info, FILE *in)
{
	int i;

	if (info->file_ehdr.e_phnum > MAX_PHDRS) {
		printc_err("elf32: too many program headers: %d\n",
			info->file_ehdr.e_phnum);
		return -1;
	}

	for (i = 0; i < info->file_ehdr.e_phnum; i++) {
		GElf_Phdr *phdr = &info->file_phdrs[i];
		if (gelf_getphdr(info->elf, i, phdr) != phdr) {
			printc_err("elf32: can't read phdr %d: %s\n",
				i, elf_errmsg(elf_errno()));
		}
	}

	return 0;
}

static int read_shdr(struct elf32_info *info, FILE *in)
{
	Elf_Scn *scn;
	int i;

	if (info->file_ehdr.e_shnum > MAX_SHDRS) {
		printc_err("elf32: too many section headers: %d\n",
			info->file_ehdr.e_shnum);
		return -1;
	}

	i = 0;
	scn = NULL;
	while ((scn = elf_nextscn(info->elf, scn)) != NULL) {
		GElf_Shdr *shdr = &info->file_shdrs[i];
		if (gelf_getshdr(scn, shdr) != shdr) {
			printc_err("elf32: can't read shdr %d: %s\n",
				i, elf_errmsg(elf_errno()));
		}
		i++;
	}

	return 0;
}

static uint32_t file_to_phys(struct elf32_info *info, uint32_t v)
{
	int i;

	for (i = 0; i < info->file_ehdr.e_phnum; i++) {
		GElf_Phdr *p = &info->file_phdrs[i];

		if (v >= p->p_offset && v - p->p_offset < p->p_filesz)
			return v - p->p_offset + p->p_paddr;
	}

	return v;
}

static int feed_section(struct elf32_info *info,
			FILE *in, uint32_t offset, uint32_t size,
			binfile_imgcb_t cb, void *user_data)
{
	uint8_t buf[1024];
	uint32_t addr = file_to_phys(info, offset);

	if (fseek(in, offset, SEEK_SET) < 0) {
		pr_error("elf32: can't seek to section");
		return -1;
	}

	while (size) {
		int ask = size > sizeof(buf) ? sizeof(buf) : size;
		int len = fread(buf, 1, ask, in);

		if (len < 0) {
			pr_error("elf32: can't read section");
			return -1;
		}

		if (cb(user_data, addr, buf, len) < 0)
			return -1;

		size -= len;
		offset += len;
		addr += len;
	}

	return 0;
}

static int read_all(struct elf32_info *info, FILE *in)
{
	memset(info, 0, sizeof(info));

	if (read_ehdr(info, in) < 0)
		return -1;

	if (info->file_ehdr.e_machine != EM_MSP430)
		printc_err("elf32: warning: unknown machine type: 0x%x 0x%x\n",
			info->file_ehdr.e_machine, EM_MSP430);

	if (read_phdr(info, in) < 0)
		return -1;
	if (read_shdr(info, in) < 0)
		return -1;

	return 0;
}

int elf32_extract(FILE *in, binfile_imgcb_t cb, void *user_data)
{
	struct elf32_info info;
	int i;

	if (read_all(&info, in) < 0)
		return -1;

	for (i = 0; i < info.file_ehdr.e_shnum; i++) {
		GElf_Shdr *s = &info.file_shdrs[i];

		if (s->sh_type == SHT_PROGBITS && s->sh_flags & SHF_ALLOC &&
		    feed_section(&info, in, s->sh_offset, s->sh_size,
				 cb, user_data) < 0)
			return -1;
	}

	return 0;
}

int elf32_check(FILE *in)
{
	int i;

	rewind(in);
	for (i = 0; i < sizeof(elf32_id); i++)
		if (fgetc(in) != elf32_id[i])
			return 0;

	return 1;
}

static GElf_Shdr *find_shdr(struct elf32_info *info, Elf32_Word type)
{
	int i;

	for (i = 0; i < info->file_ehdr.e_shnum; i++) {
		GElf_Shdr *s = &info->file_shdrs[i];

		if (s->sh_type == type) {
			return s;
		}
	}

	return NULL;
}

static int syms_load_strings(struct elf32_info *info, FILE *in, GElf_Shdr *s)
{
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(info->elf, scn)) != NULL) {
		GElf_Shdr shdr_;
		GElf_Shdr *shdr;
		if ((shdr = gelf_getshdr(scn, &shdr_)) != NULL) {
			if (shdr->sh_type == SHT_SYMTAB) {
				info->string_data = elf_getdata(scn, NULL);
				if (info->string_data == NULL) {
					printc_err("elf32: error from elf_getdata: %s\n",
						elf_errmsg(elf_errno()));
					return -1;
				}
				if (info->string_data->d_size == 0) {
					printc_err("elf32: symbol table is empty\n");
					return -1;
				}
				return 0;
			}
		}
	}
	return 0;
}

#ifndef STT_COMMON
#define STT_COMMON 5
#endif

static int syms_load_syms(struct elf32_info *info, FILE *in,
			  GElf_Shdr *s)
{
	const char sym_debug = 0;
	int number = 0;
	int added = 0;
	char *name;

	/* now loop through the symbol table and print it*/
#if 1
	/* Good: This works. */
	Elf32_Sym *esym;
	Elf32_Sym *lastsym;

	esym = (Elf32_Sym*) info->string_data->d_buf;
	lastsym = (Elf32_Sym*) ((char*)info->string_data->d_buf
			+ info->string_data->d_size);
	for (; esym && (esym < lastsym); esym++) {
#else
	/* BAD: For some reason, st_value = 0 for all symbols? */
	GElf_Sym isym;
	GElf_Sym *esym;

	while ((esym = gelf_getsym(info->string_data, number, &isym))) {
#endif
		int st;
		st = ELF32_ST_TYPE(esym->st_info);
		name = elf_strptr(info->elf, s->sh_link, (size_t)esym->st_name);
		if (sym_debug) {
			printc("[%3d] name:%16s st:%d sz:%d info:%d other:%d value:%d ",
				number,
				name ? name : "<NULL>",
				st,
				esym->st_size,
				esym->st_info,
				esym->st_other,
				esym->st_value);
		}
		if ((name != NULL && name[0] != 0) &&
				(st == STT_OBJECT || st == STT_FUNC ||
				st == STT_SECTION || st == STT_COMMON ||
				st == STT_TLS)) {
			if (sym_debug) {
				printc("stab_set(%s, %d)\n", name, esym->st_value);
			}
			if (stab_set(name, esym->st_value) < 0) {
				printc_err("elf32: stab_set #%d failed\n", number);
				return -1;
			}
			added++;
		} else {
			if (sym_debug) {
				printc("was ignored\n");
			}
		}
		if (name == NULL) {
			printc_err("elf32: null symbol name %s\n",
				elf_errmsg(elf_errno()));
			exit(-1);
		}
		number++;
	}
	printc("load_syms found %d symbols, added %d\n", number, added);

	return 0;
}

int elf32_syms(FILE *in)
{
	struct elf32_info info;
	GElf_Shdr *s;
	int ret = 0;

	if (read_all(&info, in) < 0)
		return -1;

	s = find_shdr(&info, SHT_SYMTAB);
	if (!s) {
		printc_err("elf32: no symbol table\n");
		return -1;
	}

	if (s->sh_link <= 0 || s->sh_link >= info.file_ehdr.e_shnum) {
		printc_err("elf32: no string table\n");
		return -1;
	}

	if (syms_load_strings(&info, in, &info.file_shdrs[s->sh_link]) < 0 ||
	    syms_load_syms(&info, in, s) < 0)
		ret = -1;

	return ret;
}
