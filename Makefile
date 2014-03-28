KARMA=./node_modules/.bin/karma
JSDOC=./node_modules/.bin/jsdoc


test:
	@$(KARMA) start --singleRun=true karma.conf.js --browsers PhantomJS

api-doc:
	$(JSDOC) --destination doc/api/ -r src

clean:
	rm -rf doc/api/ coverage/

.PHONY: test
