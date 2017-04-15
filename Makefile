TARGETS=all check clean clobber distclean install uninstall
TARGET=all

PREFIX=${DESTDIR}/opt
BINDIR=${PREFIX}/bin
SUBDIRS=

ifeq	(${MAKE},gmake)
	INSTALL=ginstall
else
	INSTALL=install
endif

.PHONY: ${TARGETS} ${SUBDIRS}

all::	untar.py

${TARGETS}::

clobber distclean:: clean

check::	untar.py
	./untar.py ${ARGS}

install:: untar.py
	${INSTALL} -D untar.py ${BINDIR}/untar

uninstall::
	${RM} ${BINDIR}/untar

ifneq	(,${SUBDIRS})
${TARGETS}::
	${MAKE} TARGET=$@ ${SUBDIRS}
${SUBDIRS}::
	${MAKE} -C $@ ${TARGET}
endif
