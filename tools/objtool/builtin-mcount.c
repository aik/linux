// SPDX-License-Identifier: GPL-2.0-or-later

#include <subcmd/parse-options.h>
#include <string.h>
#include <stdlib.h>
#include <objtool/builtin.h>
#include <objtool/objtool.h>

bool mnop;

static const char * const mcount_usage[] = {
	"objtool mcount [<options>] file.o",
	NULL,
};

static const char * const env_usage[] = {
	"OBJTOOL_ARGS=\"<options>\"",
	NULL,
};

const struct option mcount_options[] = {
	OPT_BOOLEAN('N', "mnop", &mnop, "nop mcount call sites"),
	OPT_END(),
};

int cmd_parse_options_mcount(int argc, const char **argv, const char * const usage[])
{
	const char *envv[16] = { };
	char *env;
	int envc;

	env = getenv("OBJTOOL_ARGS");
	if (env) {
		envv[0] = "OBJTOOL_ARGS";
		for (envc = 1; envc < ARRAY_SIZE(envv); ) {
			envv[envc++] = env;
			env = strchr(env, ' ');
			if (!env)
				break;
			*env = '\0';
			env++;
		}

		parse_options(envc, envv, mcount_options, env_usage, 0);
	}

	argc = parse_options(argc, argv, mcount_options, usage, 0);
	if (argc != 1)
		usage_with_options(usage, mcount_options);
	return argc;
}

int cmd_mcount(int argc, const char **argv)
{
	const char *objname;
	struct objtool_file *file;
	int ret;

	argc = cmd_parse_options_mcount(argc, argv, mcount_usage);
	objname = argv[0];

	file = objtool_open_read(objname);
	if (!file)
		return 1;

	ret = objtool_mcount(file);
	if (ret)
		return ret;

	if (file->elf->changed)
		return elf_write(file->elf);

	return 0;
}
