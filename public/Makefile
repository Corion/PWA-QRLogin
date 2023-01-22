# This file is run on deployment to create the compressed assets

ASSETS := $(wildcard *.js *.css *.html locations.json js/*.js css/*.css)
ZIPPEDASSETS := $(addsuffix .gz,$(ASSETS))
PERL:=/home/corion/perl-5.24/bin/perl

.PHONY: deploy

%.gz: %
	gzip -fk9 $<

manifest.json: $(ASSETS)
	PERLLIB= $(PERL) -w ../bump-manifest-version.pl -f --service-worker=sw.js

deploy: $(ZIPPEDASSETS) manifest.json.gz
