PREFIX ?= packages
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share/mcp-server-gdb
CONFIGDIR ?= $(DATADIR)/configs
SCRIPTDIR ?= $(DATADIR)/scripts
CARGO ?= cargo

.PHONY: all build install uninstall clean

all: build

build:
	$(CARGO) build --release

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFIGDIR)
	install -d $(DESTDIR)$(SCRIPTDIR)
	install -m 755 target/release/mcp-server-gdb $(DESTDIR)$(BINDIR)/mcp-server-gdb
	sed -e "s|^extra_plugins_dir *=.*|extra_plugins_dir = $(SCRIPTDIR)|" configs/gef.rc \
		> $(DESTDIR)$(CONFIGDIR)/gef.rc
	install -m 644 scripts/gef_json.py $(DESTDIR)$(SCRIPTDIR)/gef_json.py

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/mcp-server-gdb
	rm -f $(DESTDIR)$(CONFIGDIR)/gef.rc
	rm -f $(DESTDIR)$(SCRIPTDIR)/gef_json.py

clean:
	$(CARGO) clean
