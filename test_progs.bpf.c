#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int simple_loop(void *ctx)
{
	int i, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	return s;
}

SEC("socket")
int simple_loop_with_if(void *ctx)
{
	int i, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)i);
		else
			bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	return s;
}

SEC("socket")
int simple_loop_with_continue(void *ctx)
{
	int i, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	return s;
}

SEC("socket")
int nested_loop(void *ctx)
{
	int i, j, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		for (j = 0; j < 100; j++)
			bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)j);
		s += v;
	}
	return s;
}

SEC("socket")
int nested_loop_with_if(void *ctx)
{
	int i, j, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		for (j = 0; j < 1000; j++) {
			if (bpf_get_prandom_u32())
				bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)j);
			else
				bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)j);
			s += v;
		}
	}
	return s;
}

SEC("socket")
int very_nested_loop(void *ctx)
{
	int i, j, k, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		for (j = 0; j < 1000; j++) {
			for (k = 0; k < 1000; k++) {
				if (bpf_get_prandom_u32())
					continue;
				bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)k);
				s += v;
			}
			bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)j);
			s += v;
		}
	}
	return s;
}

SEC("socket")
int sequence_of_loops(void *ctx)
{
	int i, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	for (i = 0; i < 100; i++) {
		if (bpf_get_prandom_u32())
			bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)i);
		else
			bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	return s;
}

SEC("socket")
int sequence_of_loops_with_nested(void *ctx)
{
	int i, j, v, s;

	s = 0;
	for (i = 0; i < 1000; i++) {
		if (bpf_get_prandom_u32())
			continue;
		bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)i);
		s += v;
	}
	for (i = 0; i < 100; i++) {
		for (j = 0; j < 1000; j++) {
			if (bpf_get_prandom_u32())
				bpf_probe_read_kernel(&v, sizeof(v), (void *)(__u64)j);
			else
				bpf_probe_read_user(&v, sizeof(v), (void *)(__u64)j);
			s += v;
		}
	}
	return s;
}

SEC("socket")
__attribute__((naked)) int irreducible1(void *ctx)
{
	asm volatile (
		"r0 = 0;\n"
		"if r1 != 1 goto 2f;\n"
	"1:\n"
		"if r1 != 2 goto 3f;\n"
	"2:\n"
		"if r1 != 3 goto 1b;\n"
	"3:\n"
		"exit;\n"
	::: "r0", "r1");
}
