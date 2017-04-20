TARGETS=alias check clean clobber distclean install links uninstall
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

links::
	cd "${BINDIR}";							\
	for a in ${ALIASES}; do						\
		if [[ "$${a}" != 'untar' ]]; then			\
			echo -e "\t$${a}";				\
			/bin/ln -svf ./untar "$${a}";			\
		fi;							\
	done

uninstall::
	${RM} ${BINDIR}/untar

ifneq	(,${SUBDIRS})
${TARGETS}::
	${MAKE} TARGET=$@ ${SUBDIRS}
${SUBDIRS}::
	${MAKE} -C $@ ${TARGET}
endif
