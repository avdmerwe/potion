# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>

PACKAGE = potion

# debian/changelog is the single source of truth for the version
VERSION := $(shell sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' debian/changelog 2>/dev/null)

ifeq ($(strip $(VERSION)),)
VERSION := 0.1.1
endif

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
datarootdir ?= $(prefix)/share
mandir      ?= $(datarootdir)/man

INSTALL    ?= install
PKG_CONFIG ?= pkg-config

# Default flags, overridable from the environment or the command line
CFLAGS  ?= -O2 -g
LDFLAGS ?=

PKGS = libevent libpcap ncurses

PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell $(PKG_CONFIG) --libs $(PKGS) 2>/dev/null)

ifeq ($(strip $(PKG_LIBS)),)
PKG_LIBS := -levent -lpcap -lncurses
endif

WARN = -Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith -Wwrite-strings	\
       -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations		\
       -Wredundant-decls -Wnested-externs -Wold-style-definition			\
       -Wvla -Wundef

ALL_CPPFLAGS = -DPOTION_VERSION='"$(VERSION)"' $(PKG_CFLAGS) $(CPPFLAGS)
ALL_CFLAGS   = -std=gnu11 $(WARN) $(CFLAGS)
ALL_LDFLAGS  = $(LDFLAGS)
ALL_LDLIBS   = $(LDLIBS) $(PKG_LIBS)

SRC =	src/capture.c		\
	src/config.c		\
	src/flow.c		\
	src/gui.c		\
	src/io.c		\
	src/link.c		\
	src/link-ether.c	\
	src/link-sll.c		\
	src/log.c		\
	src/main.c		\
	src/sig.c

OBJ = $(SRC:.c=.o)
DEP = $(OBJ:.o=.d)

.PHONY: all check clean distclean install uninstall

all: $(PACKAGE)

$(PACKAGE): $(OBJ)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $(OBJ) $(ALL_LDLIBS)

%.o: %.c
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -MMD -MP -c -o $@ $<

# POTION_VERSION is read out of the changelog, so a release bump has to
# rebuild everything that was compiled with the old value
$(OBJ) $(TESTS): debian/changelog

TESTS = tests/test_capture tests/test_flow
TEST_DEP = $(TESTS:=.d)

check: $(TESTS)
	@set -e; for t in $(TESTS); do ./$$t; done

# The prerequisite lists are named rather than expanded with $^, because
# the generated .d files add headers as prerequisites and those must not
# reach the link line.
TEST_CAPTURE_OBJ = src/flow.o src/link.o src/link-ether.o src/link-sll.o src/log.o
TEST_FLOW_OBJ    = src/flow.o src/log.o

# test_capture.c includes src/capture.c so it can reach the static parser;
# -MMD is what keeps it from testing a stale copy of it
tests/test_capture: tests/test_capture.c $(TEST_CAPTURE_OBJ)
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -MMD -MP -MF $@.d $(ALL_LDFLAGS) \
		-o $@ tests/test_capture.c $(TEST_CAPTURE_OBJ) $(ALL_LDLIBS)

tests/test_flow: tests/test_flow.c $(TEST_FLOW_OBJ)
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -MMD -MP -MF $@.d $(ALL_LDFLAGS) \
		-o $@ tests/test_flow.c $(TEST_FLOW_OBJ) $(ALL_LDLIBS)

install: all
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -m 0755 $(PACKAGE) $(DESTDIR)$(bindir)/$(PACKAGE)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 0644 man/$(PACKAGE).1 $(DESTDIR)$(mandir)/man1/$(PACKAGE).1

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(PACKAGE)
	rm -f $(DESTDIR)$(mandir)/man1/$(PACKAGE).1

clean:
	rm -f $(PACKAGE) $(TESTS) $(TEST_DEP)
	rm -f src/*.o src/*.d
	rm -f src/*.gch tests/*.gch

distclean: clean

-include $(DEP) $(TEST_DEP)
