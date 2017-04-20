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

all::	untar.py

${TARGETS}::

clobber distclean:: clean

check::	untar.py
	./untar.py ${ARGS}

install:: untar.py
	${INSTALL} -D untar.py ${BINDIR}/untar
	${MAKE} TARGET=alias

ALIASES	:= $(shell python ./untar.py --alias)

vars::
	echo "ALIASES=${ALIASES}"

alias::
	cd "${BINDIR}";							\
	for a in ${ALIASES}; do						\
		if [[ "$${a}" != 'untar' ]]; then			\
			/bin/ln -svf ./untar "$${a}";			\
		fi;							\
	done

uninstall::
	cd "${BINDIR}" && ${RM} untar ${ALIASES}

ifneq	(,${SUBDIRS})
${TARGETS}::
	${MAKE} TARGET=$@ ${SUBDIRS}
${SUBDIRS}::
	${MAKE} -C $@ ${TARGET}
endif
