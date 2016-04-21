SUBDIRS = src

man1_MANS = ipdecap.1
EXTRA_DIST = Contributors tools unit_tests README.md autogen.sh ipdecap.1

check: all
	cd unit_tests && $(MAKE) $@

clean:
	cd src && $(MAKE) $@
	cd unit_tests && $(MAKE) $@
