/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <objtool/cfi.h>
#include <objtool/arch.h>

int decode_instructions(struct objtool_file *file);
struct reloc *insn_reloc(struct objtool_file *file, struct instruction *insn);
void remove_insn_ops(struct instruction *insn);
struct symbol *find_call_destination(struct section *sec, unsigned long offset);
int create_mcount_loc_sections(struct objtool_file *file);
struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset);

#define sym_for_each_insn(file, sym, insn)                              \
	for (insn = find_insn(file, sym->sec, sym->offset);             \
	     insn && &insn->list != &file->insn_list &&                 \
		insn->sec == sym->sec &&                                \
		insn->offset < sym->offset + sym->len;                  \
	     insn = list_next_entry(insn, list))

#endif /* UTILS_H */
