PKGS =		libssl libcrypto json-c uuid
TARGET =	rmbt

GIT_VERSION := $(shell git describe --abbrev=9 --dirty --always --tags)

WARNINGS =	-Wall -Wextra -Wformat=2 -Wswitch-default -Wcast-align -Wpointer-arith \
    -Wbad-function-cast -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
    -Wcast-qual -Wshadow -Wwrite-strings -Wconversion -Wunreachable-code \
    -pedantic -Wdisabled-optimization -Winit-self -Wmissing-declarations -Wmissing-include-dirs \
    -Wmissing-prototypes -Wparentheses -Wredundant-decls -Wsequence-point \
    -Wsign-compare -Wuninitialized -Wno-format-nonliteral -Wmissing-noreturn

OPTS =		-fno-common -fstrict-aliasing -fmessage-length=0

CFLAGS =	-std=gnu11 -O3 -g $(WARNINGS) $(OPTS) -DGIT_VERSION=\"$(GIT_VERSION)\"
CFLAGS +=	$(shell pkg-config --cflags $(PKGS))

DEBUG_CFLAGS=	-Og

.PHONY:		all clean debug force

all:		$(TARGET)

debug:		CFLAGS += $(DEBUG_CFLAGS)
debug:		all

.git_version:	force
	@echo '$(GIT_VERSION)' | cmp -s - $@ || echo '$(GIT_VERSION)' > $@

D_SRC =		src

LIBS =		-pthread -lrt $(shell pkg-config --libs $(PKGS))

C_FILES =	$(wildcard $(D_SRC)/*.c)
OBJS =		$(patsubst %.c,%.o,$(C_FILES))
DEP =		$(OBJS:.o=.d)  # one dependency file for each source

$(OBJS):	.git_version

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

-include $(DEP)   # include all dep files in the makefile

# rule to generate a dep file by using the C preprocessor
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
	
clean:
	-rm -f $(OBJS) $(TARGET) $(DEP)
