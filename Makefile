cfiles:=loops-pg.c disasm.c
ofiles:=$(cfiles:.c=.o)
jfiles:=$(cfiles:.c=.o.json)
dfiles:=$(cfiles:.c=.o.d)

bpf_cfiles:=test_progs.bpf.c
bpf_ofiles:=$(bpf_cfiles:.c=.o)
bpf_jfiles:=$(bpf_cfiles:.c=.o.json)
bpf_dfiles:=$(bpf_cfiles:.c=.o.d)

jfiles+=$(bpf_jfiles)
dfiles+=$(bpf_dfiles)

selfdir:=$(realpath .)
cc:=clang
cflags=-g -Wall -fsanitize=address -Wno-override-init
cflags+=$(shell pkg-config --cflags libbpf)
cflags+=-I. -Ilibbpf/include/uapi/
ldflags=-fsanitize=address $(shell pkg-config --libs libbpf) -lelf -lz
bpf_cflags=-g -O --target=bpf
bpf_cflags+=-I$(selfdir)/libbpf-build/include/

q:=$(if $(V),,@)

default: loops-pg $(bpf_ofiles) compile_commands.json

-include $(dfiles)

%.bpf.o: %.bpf.c
	$(q)$(cc) $(bpf_cflags) -MD -MF $@.d -MJ $@.json -c $< -o $@

%.o: %.c
	$(q)$(cc) $(cflags) -MD -MF $@.d -MJ $@.json -c $< -o $@

$(jfiles): $(ofiles)

compile_commands.json: $(jfiles)
	$(q)echo '['	 > $@
	$(q)cat  $^	| sed 's/,$$//' >> $@
	$(q)echo ']'  	>> $@

export PKG_CONFIG_PATH=$(selfdir)/libbpf-build/lib64/pkgconfig/:$PKG_CONFIG_PATH

loops-pg: libbpf-build $(ofiles)
	$(q)$(cc) $(ofiles) $(ldflags) -o $@

libbpf-build: libbpf/src/*.c libbpf/src/*.h
	$(q)mkdir -p libbpf-build
	$(q)BUILD_STATIC_ONLY=y \
	    OBJDIR=$(selfdir)/libbpf-build \
	    PREFIX=$(selfdir)/libbpf-build \
	    make V=$(q) -j -C $(selfdir)/libbpf/src install

clean:
	$(q)rm -f $(ofiles) $(jfiles) $(dfiles) $(bpf_ofiles) loops-pg compile_commands.json

full-clean: clean
	$(q)rm -rf libbpf-build

.PHONY: clean full-clean libbpf
