#include <argp.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "disasm.h"

typedef unsigned long  u64;
typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char  u8;

struct bpf_iarray {
	int cnt;
	u32 items[];
};

struct bpf_prog {
	struct bpf_insn *insnsi;
	u32 len;
};

struct bpf_subprog_info {
	u32 start; /* insn idx of function entry point */
	u32 postorder_start; /* The idx to the env->cfg.insn_postorder */
};

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_subprog_info *subprog_info;
	struct bpf_iarray *succ;
	struct bpf_iarray **preds;
	int *idoms;
	int subprog_cnt;
	struct {
		int *insn_postorder;
		int cur_postorder;
	} cfg;
};

#define kvcalloc(sz, num, _) calloc(sz, num)
#define kvfree(v) free(v)

#define log_error(fmt, ...) __log_error(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

__attribute__((format(printf, 3, 4)))
static void __log_error(const char *file, int line, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "%s:%d:(errno=%d,%s): ",
		file, line, errno, strerror(errno));
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static bool bpf_is_ldimm64(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static int bpf_jmp_offset(struct bpf_insn *insn)
{
	u8 code = insn->code;

	if (code == (BPF_JMP32 | BPF_JA))
		return insn->imm;
	return insn->off;
}

static struct bpf_iarray *bpf_insn_successors(struct bpf_verifier_env *env, u32 idx)
{
	static const struct opcode_info {
		bool can_jump;
		bool can_fallthrough;
	} opcode_info_tbl[256] = {
		[0 ... 255] = {.can_jump = false, .can_fallthrough = true},
	#define _J(code, ...) \
		[BPF_JMP   | code] = __VA_ARGS__, \
		[BPF_JMP32 | code] = __VA_ARGS__

		_J(BPF_EXIT,  {.can_jump = false, .can_fallthrough = false}),
		_J(BPF_JA,    {.can_jump = true,  .can_fallthrough = false}),
		_J(BPF_JEQ,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JNE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JLT,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JLE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JGT,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JGE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSGT,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSGE,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSLT,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSLE,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JCOND, {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSET,  {.can_jump = true,  .can_fallthrough = true}),
	#undef _J
	};
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = &prog->insnsi[idx];
	const struct opcode_info *opcode_info;
	struct bpf_iarray *succ;
	int insn_sz;

	/* pre-allocated array of size up to 2; reset cnt, as it may have been used already */
	succ = env->succ;
	succ->cnt = 0;

	opcode_info = &opcode_info_tbl[BPF_CLASS(insn->code) | BPF_OP(insn->code)];
	insn_sz = bpf_is_ldimm64(insn) ? 2 : 1;
	if (opcode_info->can_fallthrough)
		succ->items[succ->cnt++] = idx + insn_sz;

	if (opcode_info->can_jump)
		succ->items[succ->cnt++] = idx + bpf_jmp_offset(insn) + 1;

	return succ;
}

enum {
	DISCOVERED = 0x1,
	EXPLORED = 0x2,
};

/*
 * For each subprogram 'i' fill array env->cfg.insn_subprogram sub-range
 * [env->subprog_info[i].postorder_start, env->subprog_info[i+1].postorder_start)
 * with indices of 'i' instructions in postorder.
 */
static int compute_postorder(struct bpf_verifier_env *env)
{
	u32 cur_postorder, i, top, stack_sz, s;
	int *stack = NULL, *postorder = NULL, *state = NULL;
	struct bpf_iarray *succ;

	postorder = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	state = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	stack = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!postorder || !state || !stack) {
		kvfree(postorder);
		kvfree(state);
		kvfree(stack);
		return -ENOMEM;
	}
	cur_postorder = 0;
	for (i = 0; i < env->subprog_cnt; i++) {
		env->subprog_info[i].postorder_start = cur_postorder;
		stack[0] = env->subprog_info[i].start;
		stack_sz = 1;
		do {
			top = stack[stack_sz - 1];
			state[top] |= DISCOVERED;
			if (state[top] & EXPLORED) {
				postorder[cur_postorder++] = top;
				stack_sz--;
				continue;
			}
			succ = bpf_insn_successors(env, top);
			for (s = 0; s < succ->cnt; ++s) {
				if (!state[succ->items[s]]) {
					stack[stack_sz++] = succ->items[s];
					state[succ->items[s]] |= DISCOVERED;
				}
			}
			state[top] |= EXPLORED;
		} while (stack_sz);
	}
	env->subprog_info[i].postorder_start = cur_postorder;
	env->cfg.insn_postorder = postorder;
	env->cfg.cur_postorder = cur_postorder;
	kvfree(stack);
	kvfree(state);
	return 0;
}

static int compute_predecessors(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insns = prog->insnsi, *insn;
	u32 *num_preds, i, len = prog->len;
	struct bpf_iarray *succ, *preds;
	void *arena;

	num_preds = calloc(sizeof(u32), prog->len);
	if (!num_preds)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		for (int s = 0; s < succ->cnt; s++)
			num_preds[succ->items[s]]++;

		if (bpf_is_ldimm64(insn))
			i++;
	}

	/* TODO: allocate this on arena */
	env->preds = calloc(sizeof(*env->preds), len);
	if (!env->preds)
		goto nomem;
	for (i = 0; i < len; i++) {
		env->preds[i] = calloc(sizeof(**env->preds) + sizeof(u32) * num_preds[i], 1);
		if (!env->preds[i])
			goto nomem;
	}

	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		for (int s = 0; s < succ->cnt; s++) {
			preds = env->preds[succ->items[s]];
			preds->items[preds->cnt++] = i;
		}

		if (bpf_is_ldimm64(insn))
			i++;
	}

	free(num_preds);
	return 0;

nomem:
	free(num_preds);
	return -ENOMEM;
}

#define iarray_for_each(item, arr)						\
	for (int ___idx = 0;							\
	     ___idx < (arr)->cnt && ({ item = (arr)->items[___idx]; 1; });	\
	     ___idx++)

static int idoms_intersect(struct bpf_verifier_env *env, int a, int b)
{
	int *postorder_nums = env->cfg.postorder_nums;
	int *idoms = env->idoms;
	int i = 0;

	/*
	 * fprintf(stderr, "idoms_intersect: a=%d, b=%d\n", a, b);
	 */
	while (a != b) {
		while (postorder_nums[a] < postorder_nums[b]) {
			/*
			 * fprintf(stderr, "idoms_intersect: a: po[%d]=%d < po[%d]=%d, %d -> %d\n",
			 * 	a, postorder_nums[a], b, postorder_nums[b], a, idoms[a]);
			 */
			a = idoms[a];
		}
		while (postorder_nums[b] < postorder_nums[a]) {
			/*
			 * fprintf(stderr, "idoms_intersect: b: po[%d]=%d < po[%d]=%d, %d -> %d\n",
			 * 	b, postorder_nums[b], a, postorder_nums[a], a, idoms[a]);
			 */
			b = idoms[b];
		}
		if (i++ > env->prog->len) {
			fprintf(stderr, "idoms_intersect: infinite loop\n");
			exit(1);
		}
	}
	return a;
}

static void compute_subprog_idoms(struct bpf_verifier_env *env, int subprog_idx)
{
	struct bpf_subprog_info *subprog = &env->subprog_info[subprog_idx];
	int start = subprog->start;
	int end = (subprog + 1)->start;
	int po_first = subprog->postorder_start;
	int po_last = (subprog + 1)->postorder_start - 1;
	int *idoms = env->idoms;
	int po_num, pred;
	bool changed;

	idoms[start] = 0;
	changed = true;
	do {
		changed = false;
		/* iterate in reverse postorder */
		for (po_num = po_last; po_num >= po_first; po_num--) {
			int idx = env->cfg.insn_postorder[po_num];
			struct bpf_iarray *preds;
			int new_idom = -1;

			iarray_for_each(pred, env->preds[idx]) {
				/*
				 * fprintf(stderr, "compute_subprog_idoms: idx=%d, idoms[%d]=%d, new_idom=%d\n",
				 * 	idx, pred, idoms[pred], new_idom);
				 */
				if (idoms[pred] == -1)
					continue;
				if (new_idom == -1)
					new_idom = pred;
				else
					new_idom = idoms_intersect(env, pred, new_idom);
			}
			if (new_idom != -1 && idoms[idx] != new_idom) {
				/*
				 * fprintf(stderr, "compute_subprog_idoms: idoms[%d] = %d\n", idx, new_idom);
				 */
				idoms[idx] = new_idom;
				changed = true;
			}
		}
	} while (changed);
}

static int compute_idoms(struct bpf_verifier_env *env)
{
	u32 len = env->prog->len;
	int *idoms, i;

	idoms = malloc(sizeof(*idoms) * len);
	if (!idoms)
		return -ENOMEM;

	env->idoms = idoms;
	for (i = 0; i < len; i++)
		idoms[i] = -1;

	for (i = 0; i < env->subprog_cnt; i++)
		compute_subprog_idoms(env, i);

	return 0;
}

struct ctx {
	char *bpf_file;
	char *bpf_prog;
	char *cfg;
	bool print;
	bool idoms;
};

enum {
  OPT_BPF_FILE = 0x100,
  OPT_BPF_PROG,
  OPT_PRINT,
  OPT_CFG,
  OPT_IDOMS,
};

static struct argp_option opts[] = {
  { "bpf-file", OPT_BPF_FILE, "<bpf-file>", 0, 0 },
  { "bpf-prog", OPT_BPF_PROG, "<bpf-prog>", 0, 0 },
  { "cfg", OPT_CFG, "<cfg-dot>", 0, 0 },
  { "idoms", OPT_IDOMS, 0, 0, 0 },
  { "print", OPT_PRINT, 0, 0, 0 },
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
  case OPT_CFG:
	  ctx->cfg = arg;
	  break;
  case OPT_PRINT:
	  ctx->print = true;
	  break;
  case OPT_IDOMS:
	  ctx->idoms = true;
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

#define INSN_BUF_SZ 128

__printf(2, 3)
void print_insn_cb(void *private_data, const char *fmt, ...)
{
	char *buf = private_data;
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, INSN_BUF_SZ, fmt, args);
	va_end(args);
}

static void print_insn_str(char *buf, const struct bpf_insn *insn)
{
	const struct bpf_insn_cbs cbs = {
		.cb_print = print_insn_cb,
		.private_data = buf,
	};

	print_bpf_insn(&cbs, insn, true);
	int len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = 0;
}

static void print_insn(FILE *file, const struct bpf_insn *insn)
{
	char buf[INSN_BUF_SZ];
	print_insn_str(buf, insn);
	fprintf(file, "%s\n", buf);
}

int print_cfg(struct bpf_verifier_env *env, const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		log_error("fopen(%s)", path);
		return -errno;
	}
	int *postorder = calloc(env->prog->len, sizeof(*postorder));
	if (!postorder)
		return -ENOMEM;
	for (int i = 0; i < env->cfg.cur_postorder; i++)
		postorder[env->cfg.insn_postorder[i]] = i;
	fprintf(f, "digraph G {\n");
	fprintf(f, "  node [fontname=monospace, shape=box, style=filled];\n");
	char buf[INSN_BUF_SZ];
	struct bpf_iarray *succ, *preds;
	for (int i = 0; i < env->prog->len; i++) {
		struct bpf_insn *insn = env->prog->insnsi + i;
		print_insn_str(buf, insn);
		fprintf(f, "  %d [label=\"%d: %-32s p#%d\"];\n",
			i, i, buf, postorder[i]);
		succ = bpf_insn_successors(env, i);
		for (int s = 0; s < succ->cnt; s++)
			fprintf(f, "  %d -> %d;\n", i, succ->items[s]);
		/*
		 * preds = env->preds[i];
		 * for (int p = 0; p < preds->cnt; p++)
		 * 	fprintf(f, "  %d -> %d [color=grey];\n", i, preds->items[p]);
		 */
		if (bpf_is_ldimm64(insn))
			i++;

	}
	free(postorder);
	fprintf(f, "}\n");
	fclose(f);
	return 0;
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
	if (!prog) {
		log_error("can't find program '%s'\n", ctx.bpf_prog);
		goto out;
	}

	const struct bpf_insn *insns = bpf_program__insns(prog);
	if (!insns) {
		log_error("bpf_program__insns");
		goto out;
	}
	int cnt = bpf_program__insn_cnt(prog);

	struct bpf_prog vprog = {
		.insnsi = (struct bpf_insn *)insns,
		.len = cnt,
	};
	union {
		struct bpf_iarray arr;
		u32 _[3];
	} succ;
	struct bpf_subprog_info subprogs[2] = { // TODO: compute me
		{ .start = 0 },
		{ .start = cnt },
	};
	struct bpf_verifier_env env = {
		.prog = &vprog,
		.succ = &succ.arr,
		.subprog_info = subprogs,
		.subprog_cnt = 1,
	};

	if (ctx.print) {
		for (int i = 0; i < cnt; i++) {
			const struct bpf_insn *insn = insns + i;
			print_insn(stdout, insn);
			if (bpf_is_ldimm64(insn))
				i++;
		}
	}

	err = compute_postorder(&env);
	if (err) {
		log_error("Can't compute postorder\n");
		goto out;
	}

	err = compute_predecessors(&env);
	if (err) {
		log_error("Can't compute predecessors\n");
		goto out;
	}

	if (ctx.idoms) {
		err = compute_idoms(&env);
		if (err) {
			log_error("Can't compute dominators\n");
			goto out;
		}
	}

	if (ctx.cfg)
		print_cfg(&env, ctx.cfg);
out:
	if (env.preds) {
		for (int i = 0; i < env.prog->len; i++)
			free(env.preds[i]);
		free(env.preds);
	}
	free(env.idoms);
	free(env.cfg.insn_postorder);
	bpf_object__close(obj);
	return 0;
}
