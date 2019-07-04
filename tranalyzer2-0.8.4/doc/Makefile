PDFLATEX := $(shell which pdflatex)
#BIBTEX   : = $(shell which bibtex)
RM        = /bin/rm -f

ifeq (, $(PDFLATEX))
	$(error "No pdflatex in $(PATH)")
endif

INFILE  = documentation

INPUT   = $(INFILE).tex
OUTPUT  = $(INFILE).pdf
PLUGINS = $(wildcard ../*/doc/*.tex)
TEMP    = $(wildcard *.aux *.bbl *.blg *.log *.out *.svn *.toc *~)

all: documentation_with_plugins_list faq

documentation_with_plugins_list: plugins_list.tex documentation

documentation:
ifeq ($(wildcard $(INFILE).toc),)
	$(PDFLATEX) $(INPUT)
endif
	$(PDFLATEX) $(INPUT)
	$(PDFLATEX) $(INPUT)

faq:
ifeq ($(wildcard faq.toc),)
	$(PDFLATEX) faq
endif
	$(PDFLATEX) faq
	$(PDFLATEX) faq

plugins_list.tex: clean_plugins_list_tex
	for p in $$(grep "\\\\documentclass\[documentation\]{subfiles}" ../plugins/*/doc/*.tex | cut -d: -f1 | grep -v t2PSkel); do \
		echo "\_ransubfile{$$p}" | sed 's/_/t/' >> plugins_list.tex; \
	done

clean_plugins_list_tex:
	@if [ -f "plugins_list.tex" ]; then \
		$(RM) "plugins_list.tex"; \
	fi

clean_tutorials:
	make -C tutorials clean

clean: clean_plugins_list_tex clean_tutorials
ifneq ($(TEMP),)
	$(RM) $(TEMP)
endif

clean_all: clean
	$(RM) $(OUTPUT) faq.pdf
