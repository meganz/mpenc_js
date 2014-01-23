// See for an example:
// https://github.com/karma-runner/karma/blob/master/test/client/karma.conf.js
module.exports = function(config) {
    config.set({
        basePath: '..',
        frameworks: ['jasmine'],

        files: [
            'js/*.js',
            'test/*.js',
        ],
        // coverage reporter generates the coverage
        reporters: ['progress'],

        preprocessors: {
            // source files, that you wanna generate coverage for
            // do not include tests or libraries
            // (these files will be instrumented by Istanbul)
            // 'src/*.js': ['coverage']
        },

        // use dots reporter, as travis terminal does not support escaping sequences
        // possible values: 'dots', 'progress'
        // CLI --reporters progress
        reporters: ['progress'],
        client: {
            mocha: {
                ui: 'tdd'
             }
        },                
        autoWatch: true,
    });
};