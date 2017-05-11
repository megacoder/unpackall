TARGETS=all alias check clean clobber distclean install uninstall
TARGET=all

PREFIX	=${DESTDIR}/opt
BINDIR	=${PREFIX}/bin
SUBDIRS	=
SHELL	=/bin/zsh

ifeq	(${MAKE},gmake)
	INSTALL=ginstall
else
	INSTALL=install
endif

.PHONY: ${TARGETS} ${SUBDIRS}

${TARGET}::

all::	untar.py sample.tar.gz sample.tar.gz.md5

${TARGETS}::

clobber distclean:: clean

ARGS	= sample.tar.gz

check::	untar.py
	./untar.py ${ARGS}

install:: install-bin install-alias

install-bin:: untar.py
	${INSTALL} -D untar.py ${BINDIR}/untar

ALIASES	:= $(shell python ./untar.py --alias)

vars::
	echo "ALIASES=${ALIASES}"

install-alias::
	cd "${BINDIR}";							\
	for a in ${ALIASES}; do						\
		case "$${a}" in						\
		default | untar )	;;				\
		* ) /bin/ln -svf ./untar "$${a}";;			\
		esac;							\
	done

uninstall:: uninstall-bin uninstall-alias

uninstall-bin::
	${RM} ${BINDIR}/untar

uninstall-alias::
	cd "${BINDIR}" && ${RM} ${ALIASES}

.PHONY:	sample

sample.tar.gz sample.tar.md5:: sample
	tar -zcf $@ sample
	md5sum sample.tar.gz >sample.tar.gz.md5

ifneq	(,${SUBDIRS})
${TARGETS}::
	${MAKE} TARGET=$@ ${SUBDIRS}
${SUBDIRS}::
	${MAKE} -C $@ ${TARGET}
endif
