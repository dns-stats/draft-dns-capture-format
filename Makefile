# Draft Makefile. You will need:
# - mmark (https://github.com/miekg/mmark)
# - xml2rfc (https://xml2rfc.tools.ietf.org/)
# - unoconv (https://github.com/dagwieers/unoconv)

DRAFT=draft-ietf-dnsop-dns-capture-format
VERSION=05

OUTDIR=draft-$(VERSION)

XML=$(OUTDIR)/$(DRAFT).xml
HTML=$(OUTDIR)/$(DRAFT)-$(VERSION).html
TXT=$(OUTDIR)/$(DRAFT)-$(VERSION).txt
GRAPHICS=\
        $(OUTDIR)/cdns_format.png $(OUTDIR)/cdns_format.svg \
        $(OUTDIR)/packet_matching.png $(OUTDIR)/packet_matching.svg \
        $(OUTDIR)/qr_data_format.png $(OUTDIR)/qr_data_format.svg \

OUTDIREXISTS=$(OUTDIR)/.f

.PHONY: clean

all: $(HTML) $(TXT) $(GRAPHICS)

$(OUTDIREXISTS): ; mkdir -p $(OUTDIR); touch $@

$(XML): $(DRAFT).md $(OUTDIREXISTS); mmark -xml2 -page $< $@

$(HTML): $(XML) ; xml2rfc --html -o $@ $<
$(TXT): $(XML) ; xml2rfc --text -o $@ $<

$(OUTDIR)/%.png: %.odg ; unoconv -o $@ --format=png $<
$(OUTDIR)/%.svg: %.odg ; unoconv -o $@ --format=svg $<

clean: ; rm $(XML) $(HTML) $(TXT) $(GRAPHICS)
