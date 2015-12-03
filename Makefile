PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

MKDIR_P = mkdir -p
INSTALL = install
LN_S = ln -s
RM = rm

all:
clean:
check:

install:
	$(MKDIR_P) $(DESTDIR)$(BINDIR)
	$(INSTALL) ostree-push $(DESTDIR)$(BINDIR)/ostree-push
	$(LN_S) -f ostree-push $(DESTDIR)$(BINDIR)/ostree-receive

uninstall:
	$(RM) -f $(DESTDIR)$(BINDIR)/ostree-push
	$(RM) -f $(DESTDIR)$(BINDIR)/ostree-receive
