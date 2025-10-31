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

struct dfs_state {
	u32 traversed:1;
	u32 next_succ:31;
};

struct loops_info {
	struct dfs_state *state;/* temporary variable */
	bool *is_header;	/* true, if node is a loop header */
	int *loop_header;	/* maps instruction at index to it's innermost loop header */
	int *irreducible;	/* list of irreducible loop headers */
	int *dfs_pos;		/* temporary variable */
	int *stack;		/* temporary variable */
	int irreducible_cnt;	/* number of elements in irreducible */
};


static void free_loops_info_tmps(struct loops_info *loops)
{
	free(loops->dfs_pos);
	free(loops->stack);
	free(loops->state);
	loops->dfs_pos = NULL;
	loops->stack = NULL;
	loops->state = NULL;
}

static void free_loops_info(struct loops_info *loops)
{
	free_loops_info_tmps(loops);
	free(loops->is_header);
	free(loops->loop_header);
	free(loops->irreducible);
	loops->is_header = NULL;
	loops->loop_header = NULL;
	loops->irreducible = NULL;
}

#define BPF_MAX_SUBPROGS 256

struct bpf_verifier_env {
	struct bpf_prog *prog;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS];
	struct bpf_iarray *succ;
	struct bpf_iarray **preds;
	int *idoms;
	struct loops_info loops;
	int subprogs_cnt;
	struct {
		int *insn_postorder;
		int *postorder_nums;
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

static void *realloc_array(void *arr, size_t old_n, size_t new_n, size_t size)
{
	void *tmp;

	tmp = realloc(arr, new_n * size);
	if (!tmp)
		return NULL;

	if (new_n > old_n)
		memset(tmp + old_n * size, 0, (new_n - old_n) * size);
	return tmp;
}

static bool bpf_is_ldimm64(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static inline bool bpf_pseudo_func(const struct bpf_insn *insn)
{
	return bpf_is_ldimm64(insn) && insn->src_reg == BPF_PSEUDO_FUNC;
}

static bool bpf_pseudo_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
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

static int cmp_subprogs(const void *a, const void *b)
{
	return ((struct bpf_subprog_info *)a)->start -
	       ((struct bpf_subprog_info *)b)->start;
}

/* Find subprogram that contains instruction at 'off' */
struct bpf_subprog_info *bpf_find_containing_subprog(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *vals = env->subprog_info;
	int l, r, m;

	if (off >= env->prog->len || off < 0 || env->subprogs_cnt == 0)
		return NULL;

	l = 0;
	r = env->subprogs_cnt - 1;
	while (l < r) {
		m = l + (r - l + 1) / 2;
		if (vals[m].start <= off)
			l = m;
		else
			r = m - 1;
	}
	return &vals[l];
}

/* Find subprogram that starts exactly at 'off' */
static int find_subprog(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *p;

	p = bpf_find_containing_subprog(env, off);
	if (!p || p->start != off)
		return -ENOENT;
	return p - env->subprog_info;
}

static int add_subprog(struct bpf_verifier_env *env, int off)
{
	int insn_cnt = env->prog->len;
	int ret;

	if (off >= insn_cnt || off < 0) {
		log_error("call to invalid destination\n");
		return -EINVAL;
	}
	ret = find_subprog(env, off);
	if (ret >= 0)
		return ret;
	if (env->subprogs_cnt >= BPF_MAX_SUBPROGS) {
		log_error("too many subprograms\n");
		return -E2BIG;
	}
	/* determine subprog starts. The end is one before the next starts */
	env->subprog_info[env->subprogs_cnt++].start = off;
	qsort(env->subprog_info, env->subprogs_cnt,
	      sizeof(env->subprog_info[0]), cmp_subprogs);
	return env->subprogs_cnt - 1;
}

static int add_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	int i, ret, insn_cnt = env->prog->len;
	struct bpf_insn *insn = env->prog->insnsi;

	/* Add entry function. */
	ret = add_subprog(env, 0);
	if (ret)
		return ret;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn))
			continue;

		ret = add_subprog(env, i + insn->imm + 1);
		if (ret < 0)
			return ret;
	}

	/* Add a fake 'exit' subprog which could simplify subprog iteration
	 * logic. 'subprogs_cnt' should not be increased.
	 */
	subprog[env->subprogs_cnt].start = insn_cnt;
	return 0;
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
	int *stack = NULL, *postorder = NULL, *state = NULL, *postorder_nums = NULL;
	u32 cur_postorder, i, top, stack_sz, s;
	struct bpf_iarray *succ;

	postorder_nums = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	postorder = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	state = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	stack = kvcalloc(env->prog->len, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!postorder || !state || !stack || !postorder_nums) {
		kvfree(postorder_nums);
		kvfree(postorder);
		kvfree(state);
		kvfree(stack);
		return -ENOMEM;
	}
	cur_postorder = 0;
	for (i = 0; i < env->subprogs_cnt; i++) {
		env->subprog_info[i].postorder_start = cur_postorder;
		stack[0] = env->subprog_info[i].start;
		stack_sz = 1;
		do {
			top = stack[stack_sz - 1];
			state[top] |= DISCOVERED;
			if (state[top] & EXPLORED) {
				postorder[cur_postorder] = top;
				postorder_nums[top] = cur_postorder;
				cur_postorder++;
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
	env->cfg.postorder_nums = postorder_nums;
	env->cfg.insn_postorder = postorder;
	env->cfg.cur_postorder = cur_postorder;
	kvfree(stack);
	kvfree(state);
	return 0;
}

static int compute_predecessors(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn;
	u32 *num_preds, i, len = prog->len;
	struct bpf_iarray *succ, *preds;

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

	for (i = 0; i < env->subprogs_cnt; i++)
		compute_subprog_idoms(env, i);

	return 0;
}

static int mark_irreducible(struct loops_info *loops, int header)
{
	int *irreducible;

	irreducible = realloc_array(loops->irreducible,
				    loops->irreducible_cnt,
				    loops->irreducible_cnt + 1,
				    sizeof(int));
	if (!irreducible)
		return -ENOMEM;

	loops->irreducible = irreducible;
	irreducible[loops->irreducible_cnt++] = header;
	return 0;
}

static void assign_header(struct loops_info *loops, int n, int h)
{
	int *loop_header = loops->loop_header;
	bool *is_header = loops->is_header;
	int *dfs_pos = loops->dfs_pos;
	int nh;

	/*
	 * printf("assign_header(n=%d, h=%d)\n", n, h);
	 */
	is_header[h] = true;

	/* Don't encode self-loops, otherwise can't reflect loops nesting structure. */
	if (n == h)
		return;

	/* Make sure that loop headers up the chain are sorted by dfs_pos. */
	while (loop_header[n] != -1) {
		nh = loop_header[n];
		if (nh == h)
			return;
		if (dfs_pos[nh] < dfs_pos[h]) {
			loop_header[n] = h;
			n = h;
			h = nh;
		} else {
			n = nh;
		}
	}
	loop_header[n] = h;
}

/*
 * As described in "A New Algorithm for Identifying Loops in Decompilation" by Wei et al,
 * adapted to be non-recursive.
 */
static int assign_loop_headers_in_subprog(struct bpf_verifier_env *env, int subprog_idx)
{
	struct loops_info *loops = &env->loops;
	struct dfs_state *state = loops->state;
	int *loop_header = loops->loop_header;
	int *dfs_pos = loops->dfs_pos;
	int *stack = loops->stack;
	int err, s, h, cur, stack_sz;
	struct bpf_iarray *succ;

	stack[0] = env->subprog_info[subprog_idx].start;
	state[0].traversed = true;
	state[0].next_succ = 0;
	dfs_pos[0] = 1;
	stack_sz = 1;
	do {
		cur = stack[stack_sz - 1];
		/*
		 * printf("cur=%d, next_succ=%d\n", cur, state[cur].next_succ);
		 */
		succ = bpf_insn_successors(env, cur);
		if (state[cur].next_succ == succ->cnt) {
			dfs_pos[cur] = 0;
			stack_sz--;
			/*
			 * printf("cur=%d, pop\n", cur);
			 */
			continue;
		}
		s = succ->items[state[cur].next_succ];
		if (!state[s].traversed) {
			/* Case A:  start -> ... -> cur -> s [unxplored] */
			/*
			 * printf("push %d\n", s);
			 */
			state[s].traversed = true;
			state[s].next_succ = 0;
			stack[stack_sz] = s;
			dfs_pos[s] = stack_sz + 1;
			stack_sz++;
			continue;
		}
		/* 's' is fully explored at this point */
		if (dfs_pos[s]) {
			/*
			 * start -> ... -> s -> cur --.
			 *                 ^          |
			 *                 '----------'
			 * Case B: 's' is in the current DFS path.
			 */
			assign_header(loops, cur, s);
		} else if (loop_header[s] == -1) {
			/*
			 * start -> ... -> ... -> s -> ... -> end
			 *           |            ^
			 *           '---> cur ---'
			 * Case C: 's' is explored, not in the current DFS path,
			 * and not a part of any loop.
			 */
		} else if (dfs_pos[loop_header[s]]) {
			/*
			 *                 .----------------------.
			 *                 v                      |
			 * start -> ... -> h -> ... -> ... -> s --'
			 *                       |            ^
			 *	                 '---> cur ---'
			 * Case D: 's' is explored, not in current DFS path,
			 * but it's innermost loop header is.
			 */
			assign_header(loops, cur, loop_header[s]);
		} else {
			// case E
			h = loop_header[s];
			err = mark_irreducible(loops, h);
			if (err)
				return err;
			/* can also mark 's' as reentry, but no need for now */
			while (loop_header[h] != -1) {
				h = loop_header[h];
				if (dfs_pos[h]) {
					assign_header(loops, cur, h);
					break;
				}
				err = mark_irreducible(loops, h);
				if (err)
					return err;
			}
		}
		state[cur].next_succ++;
	} while (stack_sz);

	return 0;
}

static int compute_loops(struct bpf_verifier_env *env)
{
	int err, i, len = env->prog->len;
	struct loops_info *loops = &env->loops;

	loops->loop_header = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	loops->is_header = kvcalloc(len, sizeof(bool), GFP_KERNEL_ACCOUNT);
	loops->dfs_pos = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	loops->state = kvcalloc(len, sizeof(struct dfs_state), GFP_KERNEL_ACCOUNT);
	loops->stack = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!loops->loop_header || !loops->dfs_pos || !loops->state || !loops->stack) {
		err = -ENOMEM;
		goto err_out;
	}
	for (i = 0; i < len; i++)
		loops->loop_header[i] = -1;
	for (i = 0; i < env->subprogs_cnt; i++) {
		err = assign_loop_headers_in_subprog(env, i);
		if (err)
			goto err_out;
	}
	free_loops_info_tmps(loops);
	return 0;

err_out:
	free_loops_info(loops);
	return err;
}

struct ctx {
	char **bpf_files;
	char *bpf_prog;
	char *cfg;
	bool print;
	bool idoms;
	bool loops;
	int bpf_files_cnt;
};

enum {
	OPT_BPF_PROG = 0x100,
	OPT_PRINT,
	OPT_CFG,
	OPT_IDOMS,
	OPT_LOOPS,
};

static struct argp_option opts[] = {
	{ "bpf-prog", OPT_BPF_PROG, "<bpf-prog>", 0, 0 },
	{ "cfg", OPT_CFG, "<cfg-dot>", 0, 0 },
	{ "idoms", OPT_IDOMS, 0, 0, 0 },
	{ "loops", OPT_LOOPS, 0, 0, 0 },
	{ "print", OPT_PRINT, 0, 0, 0 },
	{ 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct ctx *ctx = state->input;
	void *tmp;

	switch (key) {
	case OPT_BPF_PROG:	ctx->bpf_prog = arg; break;
	case OPT_CFG:		ctx->cfg = arg; break;
	case OPT_PRINT:	ctx->print = true; break;
	case OPT_IDOMS:	ctx->idoms = true; break;
	case OPT_LOOPS:	ctx->loops = true; break;
	case ARGP_KEY_ARG:
		tmp = realloc_array(ctx->bpf_files,
				    ctx->bpf_files_cnt,
				    ctx->bpf_files_cnt + 1,
				    sizeof(char *));
		if (!tmp)
			return -ENOMEM;
		ctx->bpf_files = tmp;
		ctx->bpf_files[ctx->bpf_files_cnt++] = arg;
		break;
	case ARGP_KEY_END:
		if (ctx->bpf_files_cnt == 0) {
			fprintf(stderr, "No files to process specified\n");
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
  opts, parse_opt, "bpf_files...", NULL
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

static int find_span(struct bpf_verifier_env *env, int idx)
{
	for (;;) {
		if (idx == env->prog->len - 1)
			break;
		struct bpf_iarray *succ, *preds;
		int sz = bpf_is_ldimm64(env->prog->insnsi + idx) ? 2 : 1;
		succ = bpf_insn_successors(env, idx);
		if (succ->cnt != 1)
			break;
		int s = idx + sz;
		if (succ->items[0] != s)
			break;
		preds = env->preds[s];
		if (preds->cnt != 1 || preds->items[0] != idx)
			break;
		if (env->idoms && env->idoms[s] != idx)
			break;
		if (env->loops.is_header && env->loops.is_header[s])
			break;
		idx += sz;
	}
	return idx;
}

#define MAX_LOOP_COLORS 7

static int get_loop_level(struct bpf_verifier_env *env, int idx)
{
	struct loops_info *loops = &env->loops;
	int level;

	if (!loops->is_header)
		return 0;

	level = 0;
	if (loops->is_header[idx])
		level += 1;
	while (loops->loop_header[idx] != -1) {
		idx = loops->loop_header[idx];
		level++;
	}
	return level;
}

static int print_cfg(struct bpf_verifier_env *env, const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		log_error("fopen(%s)", path);
		return -errno;
	}
	fprintf(f, "digraph G {\n");
	fprintf(f, "  node [fontname=monospace, shape=box, style=filled];\n");
	char buf[INSN_BUF_SZ];
	int *span_start2end = calloc(env->prog->len, sizeof(int));
	int *span_end2start = calloc(env->prog->len, sizeof(int));
	if (!span_start2end || !span_end2start)
		goto nomem;
	for (int i = 0; i < env->prog->len; i++) {
		int j = find_span(env, i);
		span_start2end[i] = j;
		span_end2start[j] = i;
		i = j;
		if (bpf_is_ldimm64(env->prog->insnsi + i))
			i++;
	}
	struct bpf_iarray *succ;
	for (int i = 0; i < env->prog->len; i++) {
		int j = span_start2end[i];
		fprintf(f, "  %d [label=\"", i);
		for (int k = i; k <= j; k++) {
			print_insn_str(buf, env->prog->insnsi + k);
			fprintf(f, "%d: %-32s p#%-3d",
				k, buf, env->cfg.postorder_nums[k]);
			int l;
			if (env->loops.loop_header && ((l = env->loops.loop_header[k]) != -1))
				fprintf(f, " l#%-3d", l);
			if (env->loops.is_header && env->loops.is_header[k])
				fprintf(f, " h");
			if (i != j)
				fprintf(f, "\\l");
			if (bpf_is_ldimm64(env->prog->insnsi + k))
				k++;
		}
		fprintf(f, "\"");
		int loop_level = get_loop_level(env, i);
		if (loop_level) {
			fprintf(f, ", fillcolor=%d", loop_level % MAX_LOOP_COLORS);
			if (env->loops.is_header[i])
				fprintf(f, ", colorscheme=set27");
			else
				fprintf(f, ", colorscheme=pastel27");
		}
		fprintf(f, "];\n");
		succ = bpf_insn_successors(env, j);
		for (int s = 0; s < succ->cnt; s++)
			fprintf(f, "  %d -> %d;\n", i, succ->items[s]);
		if (env->idoms && env->idoms[i] >= 0)
			fprintf(f, "  %d -> %d [color=red];\n", span_end2start[env->idoms[i]], i);
		i = j;
		if (bpf_is_ldimm64(env->prog->insnsi + i))
			i++;
	}
	free(span_start2end);
	free(span_end2start);
	fprintf(f, "}\n");
	fclose(f);
	return 0;
nomem:
	free(span_start2end);
	free(span_end2start);
	return -ENOMEM;
}

static int max(int a, int b)
{
	return a > b ? a : b;
}

static int process_one_prog(struct ctx *ctx, const char *path, const char *prog_name)
{
	int loop_headers_num = -1;
	int max_loop_nesting = -1;
	int irreducible_cnt = -1;

	struct bpf_program *prog = NULL;
	struct bpf_object *obj = NULL;
	int err;

	struct bpf_prog vprog;
	union {
		struct bpf_iarray arr;
		u32 _[3];
	} succ;
	struct bpf_verifier_env env = {
		.prog = &vprog,
		.succ = &succ.arr,
	};

	fprintf(stderr, "process_one_prog(%s,%s)\n", path, prog_name);
	obj = prepare_obj(path, prog_name, &prog);
	if (!obj)
		goto out;
	if (!prog) {
		log_error("can't find program '%s'\n", prog_name);
		goto out;
	}

	const struct bpf_insn *insns = bpf_program__insns(prog);
	if (!insns) {
		log_error("bpf_program__insns");
		goto out;
	}

	vprog.insnsi = (struct bpf_insn *)insns;
	vprog.len = bpf_program__insn_cnt(prog);

	if (ctx->print) {
		for (int i = 0; i < vprog.len; i++) {
			const struct bpf_insn *insn = insns + i;
			print_insn(stdout, insn);
			if (bpf_is_ldimm64(insn))
				i++;
		}
	}

	err = add_subprogs(&env);
	if (err) {
		log_error("Can't compute subprogs\n");
		goto out;
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

	if (ctx->idoms) {
		err = compute_idoms(&env);
		if (err) {
			log_error("Can't compute dominators\n");
			goto out;
		}
	}

	if (ctx->loops) {
		err = compute_loops(&env);
		if (err) {
			log_error("Can't compute loop\n");
			goto out;
		}
		/*
		 * printf("Irreducible loops count: %d\n", env.loops.irreducible_cnt);
		 * for (int i = 0; i < env.loops.irreducible_cnt; i++)
		 * 	printf("  %d\n", env.loops.irreducible[i]);
		 */
		irreducible_cnt = env.loops.irreducible_cnt;
		loop_headers_num = 0;
		for (int i = 0; i < env.prog->len; i++) {
			loop_headers_num += env.loops.is_header[i] ? 1 : 0;
			max_loop_nesting = max(max_loop_nesting, get_loop_level(&env, i));
		}
	}

	if (ctx->cfg)
		print_cfg(&env, ctx->cfg);

out:
	;
	const char *file_name = strrchr(path, '/');
	if (file_name)
		file_name += 1;
	else
		file_name = path;
	printf("%-48s %-32s %-5d %-11d %-11d\n", file_name, prog_name, loop_headers_num, max_loop_nesting, irreducible_cnt);
	if (env.preds) {
		for (int i = 0; i < env.prog->len; i++)
			free(env.preds[i]);
		free(env.preds);
	}
	free(env.idoms);
	free(env.cfg.insn_postorder);
	free(env.cfg.postorder_nums);
	free_loops_info(&env.loops);
	bpf_object__close(obj);
	return 0;
}

int main(int argc, char *argv[])
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct ctx ctx = {};
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &ctx);
	if (err)
		goto out;
	printf("%-48s %-32s %-5s %-11s %-11s\n",
	       "file", "prog", "loops", "max nesting", "irreducible");
	for (int i = 0; i < ctx.bpf_files_cnt; i++) {
		const char *bpf_file = ctx.bpf_files[i];
		if (!ctx.bpf_prog) {
			obj = bpf_object__open_file(bpf_file, NULL);
			if (!obj)
				goto out;
			bpf_object__for_each_program(prog, obj) {
				process_one_prog(&ctx, bpf_file, bpf_program__name(prog));
			}
			bpf_object__close(obj);
		} else {
			process_one_prog(&ctx, bpf_file, ctx.bpf_prog);
		}
	}
out:
	free(ctx.bpf_files);
	return 0;
}
