# Build directory.
BUILDDIR = build

# Libraries to omit when building mpenc-shared.js.
PARTIAL_OMIT = asmcrypto.js jsbn jodid25519
SHARED_JS_FILES = node_modules/asmcrypto.js/asmcrypto.js node_modules/jsbn/index.js node_modules/jodid25519/build/jodid25519-shared.js

KARMA  = ./node_modules/.bin/karma
JSDOC  = ./node_modules/.bin/jsdoc
R_JS   = ./node_modules/.bin/r.js
ALMOND = ./node_modules/almond/almond
R_JS_ALMOND_OPTS = baseUrl=src name=../$(ALMOND) wrap.startFile=almond.0 wrap.endFile=almond.1
UGLIFY = ./node_modules/.bin/uglifyjs
ASMCRYPTO_MODULES = utils,aes-cbc,aes-ccm,sha1,sha256,sha512,hmac-sha1,hmac-sha256,hmac-sha512,pbkdf2-hmac-sha1,pbkdf2-hmac-sha256,pbkdf2-hmac-sha512,rng,bn,rsa-pkcs1,globals-rng,globals

all: test test-shared dist

test: $(KARMA)
	$(KARMA) start --singleRun=true karma.conf.js --browsers PhantomJS

api-doc: $(JSDOC)
	$(JSDOC) --destination doc/api/ --private \
                 --configure jsdoc.json \
                 --recurse src/

$(BUILDDIR)/build-config-static.js: src/config.js Makefile
	mkdir -p $(BUILDDIR)
	tail -n+2 "$<" > "$@"

$(BUILDDIR)/build-config-shared.js: src/config.js Makefile
	mkdir -p $(BUILDDIR)
	tail -n+2 "$<" > "$@.tmp"
	for i in $(PARTIAL_OMIT); do \
		sed -i -e "s,node_modules/$$i/.*\",build/$$i-dummy\"," "$@.tmp"; \
		touch $(BUILDDIR)/$$i-dummy.js; \
	done
	mv "$@.tmp" "$@"

$(BUILDDIR)/mpenc-static.js: build-static
build-static: $(R_JS) $(BUILDDIR)/build-config-static.js
	$(R_JS) -o $(BUILDDIR)/build-config-static.js out="$(BUILDDIR)/mpenc-static.js" \
	  $(R_JS_ALMOND_OPTS) include=mpenc optimize=none

$(BUILDDIR)/mpenc-shared.js: build-shared
build-shared: $(R_JS) $(BUILDDIR)/build-config-shared.js
	$(R_JS) -o $(BUILDDIR)/build-config-shared.js out="$(BUILDDIR)/mpenc-shared.js" \
	  $(R_JS_ALMOND_OPTS) include=mpenc optimize=none

test-static: test/build-test-static.js build-static
	./$< ../$(BUILDDIR)/mpenc-static.js

test-shared: test/build-test-shared.js build-shared
	./$< ../$(BUILDDIR)/mpenc-shared.js $(SHARED_JS_FILES)

$(BUILDDIR)/%.min.js: $(BUILDDIR)/%.js
	$(UGLIFY) $< -o $@ --source-map $@.map --mangle --compress --lint

dist: $(BUILDDIR)/mpenc-shared.min.js $(BUILDDIR)/mpenc-static.js

dependencies:
	npm install
	cd node_modules/asmcrypto.js && npm install && node_modules/.bin/grunt --with=$(ASMCRYPTO_MODULES)
	cd ../..
	cd node_modules/jodid25519 && make build-shared
	cd ../..

$(KARMA) $(JSDOC) $(R_JS) $(UGLIFY): dependencies

clean:
	rm -rf doc/api/ coverage/ build/

.PHONY: all test api-doc clean
.PHONY: build-static build-shared test-static test-shared dist
