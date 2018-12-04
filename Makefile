# Draft Makefile. You will need:
# - mmark (https://github.com/miekg/mmark)
# - xml2rfc (https://xml2rfc.tools.ietf.org/)
# - unoconv (https://github.com/dagwieers/unoconv)

DRAFT=draft-ietf-dnsop-dns-capture-format
VERSION=10

CDDL=c-dns.cddl

OUTDIR=draft-$(VERSION)

XML=$(OUTDIR)/$(DRAFT).xml
HTML=$(OUTDIR)/$(DRAFT)-$(VERSION).html
TXT=$(OUTDIR)/$(DRAFT)-$(VERSION).txt

OUTDIREXISTS=$(OUTDIR)/.f

.PHONY: clean

all: $(HTML) $(TXT) $(GRAPHICS)

$(OUTDIREXISTS): ; mkdir -p $(OUTDIR); touch $@

$(XML): $(DRAFT).md $(CDDL) $(OUTDIREXISTS); mmark -xml2 -page $< $@

$(HTML): $(XML) ; xml2rfc --html -o $@ $<
$(TXT): $(XML) ; xml2rfc --text -o $@ $<

clean: ; rm $(XML) $(HTML) $(TXT)
