#include <argp.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <string.h>
#include "disasm.h"

#define log_error(fmt, ...) __log_error(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

__attribute__((format(printf, 3, 4)))
static void __log_error(const char *file, int line, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "%s:%d:(errno=%d,%s):",
		file, line, errno, strerror(errno));
	vfprintf(stderr, fmt, args);
	va_end(args);
}

struct ctx {
	char *bpf_file;
	char *bpf_prog;
};

enum {
  OPT_BPF_FILE = 0x100,
  OPT_BPF_PROG,
};

static struct argp_option opts[] = {
  { "bpf-file", OPT_BPF_FILE, "<bpf-file>", 0, 0 },
  { "bpf-prog", OPT_BPF_PROG, "<bpf-prog>", 0, 0 },
  { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct ctx *ctx = state->input;

  switch (key) {
  case OPT_BPF_FILE:
	  ctx->bpf_file = arg;
	  break;
  case OPT_BPF_PROG:
	  ctx->bpf_prog = arg;
	  break;
  case ARGP_KEY_END:
	  if (!ctx->bpf_file || !ctx->bpf_prog) {
		  fprintf(stderr, "Mandatory arguments %s and %s are absent\n", opts[0].name, opts[1].name);
		  argp_state_help(state, stderr, ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR);
		  return ARGP_ERR_UNKNOWN;
	  }
	  break;
  default:
	  return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {
  opts, parse_opt, NULL, NULL
};

static struct bpf_object *prepare_obj(const char *path, const char *prog_name,
				      struct bpf_program **tgt_prog)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	bool load;
	int err;

	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		return NULL;

	bpf_object__for_each_program(prog, obj) {
		load = strcmp(bpf_program__name(prog), prog_name) == 0;
		bpf_program__set_autoload(prog, load);
		if (load)
			*tgt_prog = prog;
	}

	err = bpf_object__prepare(obj);
	if (err) {
		bpf_object__close(obj);
		return NULL;
	}

	return obj;
}

__printf(2, 3)
void print_insn_cb(void *private_data, const char *fmt, ...)
{
	FILE *file = private_data;
	va_list args;

	va_start(args, fmt);
	vfprintf(file, fmt, args);
	va_end(args);
}

static void print_insn(FILE *file, const struct bpf_insn *insn)
{
	const struct bpf_insn_cbs cbs = {
		.cb_print = print_insn_cb,
		.private_data = file,
	};

	print_bpf_insn(&cbs, insn, true);
}

static bool bpf_is_ldimm64(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

int main(int argc, char *argv[])
{
	struct bpf_program *prog = NULL;
	struct bpf_object *obj = NULL;
	struct ctx ctx = {};
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &ctx);
	if (err)
		goto out;

	obj = prepare_obj(ctx.bpf_file, ctx.bpf_prog, &prog);
	if (!obj)
		goto out;

	const struct bpf_insn *insns = bpf_program__insns(prog);
	if (!insns) {
		log_error("bpf_program__insns");
		goto out;
	}
	int cnt = bpf_program__insn_cnt(prog);

	for (int i = 0; i < cnt; i++) {
		const struct bpf_insn *insn = insns + i;

		print_insn(stdout, insn);
		if (bpf_is_ldimm64(insn))
			i++;
	}
out:
	bpf_object__close(obj);
	return 0;
}
