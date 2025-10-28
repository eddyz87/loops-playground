cfiles:=loops-pg.c disasm.c
ofiles:=$(cfiles:.c=.o)
jfiles:=$(cfiles:.c=.o.json)
dfiles:=$(cfiles:.c=.o.d)
selfdir:=$(realpath .)
cc:=clang
cflags=-g -fsanitize=address $(shell pkg-config --cflags libbpf) -I.
ldflags=-fsanitize=address $(shell pkg-config --libs libbpf) -lelf -lz
q:=$(if $(V),,@)

default: loops-pg

-include $(dfiles)

%.o: %.c
	$(q)$(cc) $(cflags) -MD -MF $@.d -MJ $@.json -c $< -o $@

$(jfiles): $(ofiles)

compile_commands.json: $(jfiles)
	$(q)echo '['	 > $@
	$(q)cat  $^	| sed 's/,$$//' >> $@
	$(q)echo ']'  	>> $@

export PKG_CONFIG_PATH=$(selfdir)/libbpf-build/lib64/pkgconfig/:$PKG_CONFIG_PATH

loops-pg: libbpf-build $(ofiles) compile_commands.json
	$(q)$(cc) $(ofiles) $(ldflags) -o $@

libbpf-build: libbpf/src/*.c libbpf/src/*.h
	$(q)mkdir -p libbpf-build
	$(q)BUILD_STATIC_ONLY=y \
	    OBJDIR=$(selfdir)/libbpf-build \
	    PREFIX=$(selfdir)/libbpf-build \
	    make V=$(q) -j -C $(selfdir)/libbpf/src install

clean:
	$(q)rm -f $(ofiles) $(jfiles) $(dfiles) loops-pg compile_commands.json

full-clean: clean
	$(q)rm -rf libbpf-build

.PHONY: clean full-clean libbpf
