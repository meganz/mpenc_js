KARMA=./node_modules/.bin/karma
JSDOC=jsdoc


test:
	@$(KARMA) start --singleRun=true karma.conf.js --browsers PhantomJS

api-doc:
	$(JSDOC) --directory=doc/api/ --allfunctions -D="title:mpEnc Library" \
		--template=doc/template \
		-D="noGlobal:true" -D="index:files" \
		src/

.PHONY: test
