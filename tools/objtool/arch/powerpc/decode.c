// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>

#include <objtool/check.h>
#include <objtool/elf.h>
#include <objtool/arch.h>
#include <objtool/warn.h>
#include <objtool/builtin.h>

int arch_decode_instruction(struct objtool_file *file, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	u32 insn;
	unsigned int opcode;
	u64 imm;

	*immediate = imm = 0;
	memcpy(&insn, sec->data->d_buf+offset, 4);
	*len = 4;
	*type = INSN_OTHER;

	opcode = (insn >> 26);

	switch (opcode) {
	case 18: /* bl */
		*type = INSN_CALL;
		break;
	}
	*immediate = imm;
	return 0;
}

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset +  insn->immediate;
}

const char *arch_nop_insn(int len)
{
	return NULL;
}
