// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <objtool/builtin.h>
#include <objtool/check.h>
#include <objtool/utils.h>
#include <objtool/warn.h>

#include <linux/objtool.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/static_call_types.h>

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset)
{
	struct instruction *insn;

	hash_for_each_possible(file->insn_hash, insn, hash, sec_offset_hash(sec, offset)) {
		if (insn->sec == sec && insn->offset == offset)
			return insn;
	}

	return NULL;
}

#define NEGATIVE_RELOC  ((void *)-1L)

struct reloc *insn_reloc(struct objtool_file *file, struct instruction *insn)
{
	if (insn->reloc == NEGATIVE_RELOC)
		return NULL;

	if (!insn->reloc) {
		if (!file)
			return NULL;

		insn->reloc = find_reloc_by_dest_range(file->elf, insn->sec,
						       insn->offset, insn->len);
		if (!insn->reloc) {
			insn->reloc = NEGATIVE_RELOC;
			return NULL;
		}
	}

	return insn->reloc;
}
void remove_insn_ops(struct instruction *insn)
{
	struct stack_op *op, *tmp;

	list_for_each_entry_safe(op, tmp, &insn->stack_ops, list) {
		list_del(&op->list);
		free(op);
	}
}


struct symbol *find_call_destination(struct section *sec, unsigned long offset)
{
	struct symbol *call_dest;

	call_dest = find_func_by_offset(sec, offset);
	if (!call_dest)
		call_dest = find_symbol_by_offset(sec, offset);

	return call_dest;
}

static unsigned long nr_insns;

int decode_instructions(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	unsigned long offset;
	struct instruction *insn;
	int ret;

	for_each_sec(file, sec) {

		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;

		if (strcmp(sec->name, ".altinstr_replacement") &&
		    strcmp(sec->name, ".altinstr_aux") &&
		    strncmp(sec->name, ".discard.", 9))
			sec->text = true;

		if (!strcmp(sec->name, ".noinstr.text") ||
		    !strcmp(sec->name, ".entry.text"))
			sec->noinstr = true;

		for (offset = 0; offset < sec->sh.sh_size; offset += insn->len) {
			insn = malloc(sizeof(*insn));
			if (!insn) {
				WARN("malloc failed");
				return -1;
			}
			memset(insn, 0, sizeof(*insn));
			INIT_LIST_HEAD(&insn->alts);
			INIT_LIST_HEAD(&insn->stack_ops);

			insn->sec = sec;
			insn->offset = offset;

			ret = arch_decode_instruction(file, sec, offset,
						      sec->sh.sh_size - offset,
						      &insn->len, &insn->type,
						      &insn->immediate,
						      &insn->stack_ops);
			if (ret)
				goto err;

			hash_add(file->insn_hash, &insn->hash, sec_offset_hash(sec, insn->offset));
			list_add_tail(&insn->list, &file->insn_list);
			nr_insns++;
		}

		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC || func->alias != func)
				continue;

			if (!find_insn(file, sec, func->offset)) {
				WARN("%s(): can't find starting instruction",
				     func->name);
				return -1;
			}

			sym_for_each_insn(file, func, insn)
				insn->func = func;
		}
	}

	if (stats)
		printf("nr_insns: %lu\n", nr_insns);

	return 0;

err:
	free(insn);
	return ret;
}

int create_mcount_loc_sections(struct objtool_file *file)
{
	struct section *sec;
	unsigned long *loc;
	struct instruction *insn;
	int idx;

	sec = find_section_by_name(file->elf, "__mcount_loc");
	if (sec) {
		INIT_LIST_HEAD(&file->mcount_loc_list);
		WARN("file already has __mcount_loc section, skipping");
		return 0;
	}

	if (list_empty(&file->mcount_loc_list))
		return 0;

	idx = 0;
	list_for_each_entry(insn, &file->mcount_loc_list, call_node)
		idx++;

	sec = elf_create_section(file->elf, "__mcount_loc", 0, sizeof(unsigned long), idx);
	if (!sec)
		return -1;

	idx = 0;
	list_for_each_entry(insn, &file->mcount_loc_list, call_node) {

		loc = (unsigned long *)sec->data->d_buf + idx;
		memset(loc, 0, sizeof(unsigned long));

		if (elf_add_reloc_to_insn(file->elf, sec,
					  idx * sizeof(unsigned long),
					  R_X86_64_64,
					  insn->sec, insn->offset))
			return -1;

		idx++;
	}

	return 0;
}
