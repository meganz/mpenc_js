KARMA  = ./node_modules/.bin/karma
JSDOC  = ./node_modules/.bin/jsdoc
R_JS   = ./node_modules/.bin/r.js
ALMOND = ./node_modules/almond/almond

BUILDDIR = build

all: test build-test

test: $(KARMA)
	$(KARMA) start --singleRun=true karma.conf.js --browsers PhantomJS

api-doc: $(JSDOC)
	$(JSDOC) --destination doc/api/ --private \
                 --configure jsdoc.json \
                 --recurse src/

$(BUILDDIR)/build-config.js: src/config.js
	mkdir -p $(BUILDDIR)
	tail -n+2 "$<" > "$@"

build: $(R_JS) $(BUILDDIR)/build-config.js
	$(R_JS) -o $(BUILDDIR)/build-config.js out="$(BUILDDIR)/mpenc.js" \
	    baseUrl=src name=../$(ALMOND) include=mpenc \
	    wrap.startFile=almond.0 wrap.endFile=almond.1

build-test: compile-test.js build
	./$< ./$(BUILDDIR)/mpenc.js

$(KARMA) $(JSDOC) $(R_JS):
	npm install

clean:
	rm -rf doc/api/ coverage/ build/

.PHONY: test api-doc build clean
