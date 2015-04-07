.PHONY: all clean run plugins $(EXE)

########################################
# USER VARIABLES

RELEASE_TAG = 0.9.9
EXE = opachat.exe
PACKNAME =
MAINSRC =
PCKDIR = ./plugins/
PCK = tweetnacl.client.opx file.opx sso.opx

PLUGIN =
PLUGINDIR =
OTHER_DEPENDS = resources/*
OPAOPT ?= --opx-dir $(PWD)/_build --warn-error pattern --slicer-check low --no-warn unused --warn-error dbgen.mongo --parser js-like --force-server

#DEBUG_OPT ?= --backtrace --display-logs --verbose 8
MONGOREMOTE=localhost:27017
RUN_OPT ?= $(DEBUG_OPT) --db-remote:webmail $(MONGOREMOTE) --db-remote:rawdata $(MONGOREMOTE) --db-remote:sessions $(MONGOREMOTE) --db-remote:tokens $(MONGOREMOTE) --smtp-server-port 2626 --no-ssl false -p 4443 --http-server-port 4443
#RUN_OPT ?= $(DEBUG_OPT) --db-remote admin:admin@localhost:10001 --db-prefix webmail --smtp-server-port 2626
SRC = $(shell cat opachat.conf | grep "src")

# MLSTATELIBS is deprecated
OPADIR ?= /usr/local

CONF_FILE = opachat.conf

COMPILOPT =

# Compiler variables
export OPACOMPILER ?= opa
MINIMAL_VERSION = 4419
FLAG = --minimal-version $(MINIMAL_VERSION)

# Build exe
default: exe

# Run Server
run: exe
	./$(EXE) $(RUN_OPT) || true ## prevent ugly make error 130 :) ##

all: clean exe

clean::
	rm -rf *.opx
	rm -rf *.opx.broken
	rm -rf *.log

version:

include Makefile.common
