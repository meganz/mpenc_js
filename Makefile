# Build directory.
BUILDDIR = build

# Dependencies - make sure you keep DEP_ALL and DEP_ALL_NAMES up-to-date
DEP_ASMCRYPTO = node_modules/asmcrypto.js/asmcrypto.js
DEP_JSBN = node_modules/jsbn/index.js
DEP_JODID = node_modules/jodid25519/build/jodid25519-shared.js
DEP_ALL = $(DEP_ASMCRYPTO) $(DEP_JSBN) $(DEP_JODID)
DEP_ALL_NAMES = asmcrypto.js jsbn jodid25519

# Build-depends - make sure you keep BUILD_DEP_ALL and BUILD_DEP_ALL_NAMES up-to-date
KARMA  = ./node_modules/.bin/karma
JSDOC  = ./node_modules/.bin/jsdoc
R_JS   = ./node_modules/.bin/r.js
ALMOND = ./node_modules/almond/almond.js
R_JS_ALMOND_OPTS = baseUrl=src name=../$(ALMOND:%.js=%) wrap.startFile=almond.0 wrap.endFile=almond.1
UGLIFY = ./node_modules/.bin/uglifyjs
BUILD_DEP_ALL = $(KARMA) $(JSDOC) $(R_JS) $(ALMOND) $(UGLIFY)
BUILD_DEP_ALL_NAMES = karma jsdoc requirejs almond uglify-js

ASMCRYPTO_MODULES = utils,aes-cbc,aes-ccm,sha1,sha256,sha512,hmac-sha1,hmac-sha256,hmac-sha512,pbkdf2-hmac-sha1,pbkdf2-hmac-sha256,pbkdf2-hmac-sha512,rng,bn,rsa-pkcs1,globals-rng,globals

all: test api-doc dist test-shared

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
	for i in $(DEP_ALL_NAMES); do \
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
	./$< ../$(BUILDDIR)/mpenc-shared.js $(DEP_ALL)

$(BUILDDIR)/%.min.js: $(BUILDDIR)/%.js
	$(UGLIFY) $< -o $@ --source-map $@.map --mangle --compress --lint

dist: $(BUILDDIR)/mpenc-shared.min.js $(BUILDDIR)/mpenc-static.js

$(DEP_ASMCRYPTO):
	npm install
	cd node_modules/asmcrypto.js && npm install && node_modules/.bin/grunt --with=$(ASMCRYPTO_MODULES)

$(DEP_JODID):
	npm install
	cd node_modules/jodid25519 && make build-shared

$(BUILD_DEP_ALL) $(DEP_JSBN):
	npm install

clean:
	rm -rf doc/api/ coverage/ build/

clean-all: clean
	rm -f $(BUILD_DEP_ALL) $(DEP_ALL)
	rm -rf $(BUILD_DEP_ALL_NAMES:%=node_modules/%) $(DEP_ALL_NAMES:%=node_modules/%)

.PHONY: all test api-doc clean clean-all
.PHONY: build-static build-shared test-static test-shared dist
