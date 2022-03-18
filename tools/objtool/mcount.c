// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <arch/elf.h>
#include <objtool/builtin.h>
#include <objtool/cfi.h>
#include <objtool/arch.h>
#include <objtool/check.h>
#include <objtool/utils.h>
#include <objtool/special.h>
#include <objtool/warn.h>

#include <linux/objtool.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/static_call_types.h>

static int classify_symbols(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;

	for_each_sec(file, sec) {
		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->bind != STB_GLOBAL)
				continue;
			if ((!strcmp(func->name, "__fentry__")) || (!strcmp(func->name, "_mcount")))
				func->fentry = true;
		}
	}

	return 0;
}

static void annotate_call_site(struct objtool_file *file,
							   struct instruction *insn, bool sibling)
{
	struct reloc *reloc = insn_reloc(file, insn);
	struct symbol *sym = insn->call_dest;

	if (!sym)
		sym = reloc->sym;

	if (sym->fentry) {
		if (sibling)
			WARN_FUNC("Tail call to _mcount !?!?", insn->sec, insn->offset);
		if (mnop) {
			if (reloc) {
				reloc->type = R_NONE;
				elf_write_reloc(file->elf, reloc);
			}
			elf_write_insn(file->elf, insn->sec,
				       insn->offset, insn->len,
				       arch_nop_insn(insn->len));

			insn->type = INSN_NOP;
		}

		list_add_tail(&insn->call_node, &file->mcount_loc_list);
		return;
	}
}

static void add_call_dest(struct objtool_file *file, struct instruction *insn,
						  struct symbol *dest, bool sibling)
{
	insn->call_dest = dest;
	if (!dest)
		return;

	remove_insn_ops(insn);

	annotate_call_site(file, insn, sibling);
}
static int add_call_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	unsigned long dest_off;
	struct symbol *dest;
	struct reloc *reloc;

	for_each_insn(file, insn) {
		if (insn->type != INSN_CALL)
			continue;

		reloc = insn_reloc(file, insn);
		if (!reloc) {
			dest_off = arch_jump_destination(insn);
			dest = find_call_destination(insn->sec, dest_off);

			add_call_dest(file, insn, dest, false);


		} else {
			add_call_dest(file, insn, reloc->sym, false);
		}
	}

	return 0;
}

static int decode_sections(struct objtool_file *file)
{
	int ret;

	ret = decode_instructions(file);
	if (ret)
		return ret;

	ret = classify_symbols(file);
	if (ret)
		return ret;

	ret = add_call_destinations(file);
	if (ret)
		return ret;

	return 0;
}


int objtool_mcount(struct objtool_file *file)
{
	int ret, warnings = 0;

	ret = decode_sections(file);
	if (ret < 0)
		return 0;

	ret = create_mcount_loc_sections(file);
	if (ret < 0)
		return 0;
	warnings += ret;
	return 0;
}
