SUBDIRS = src

man1_MANS = ipdecap.1
EXTRA_DIST = Contributors

check: all
	cd unit_tests && $(MAKE) $@

clean:
	cd src && $(MAKE) $@
	cd unit_tests && $(MAKE) $@
