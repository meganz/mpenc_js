// Karma configuration.

module.exports = function(config) {
  config.set({
    // Base path, that will be used to resolve files and exclude.
    basePath: '',

    // Frameworks to use.
    frameworks: ['requirejs', 'mocha', 'chai', 'sinon'],

    // List of files/patterns to load in the browser.
    // {included: false} files are loaded by requirejs
    files: [
        // Dependency-based load order of library modules.
        // modules that already follow AMD need included: false
        {pattern: 'node_modules/es6-collections/es6-collections.js', included: false},
        'node_modules/jsbn/index.js',
        'node_modules/asmcrypto.js/asmcrypto.js',
        {pattern: 'node_modules/jodid25519/jodid25519.js', included: false},
        {pattern: 'node_modules/lru-cache/**/*.js', included: false},
        {pattern: 'node_modules/megalogger/**/*.js', included: false},
        // karma-sinon does not yet integrate with requirejs, so we have to do this hack
        {pattern: 'node_modules/sinon/lib/**/*.js', included: false},

        // Ours.
        'src/config.js',
        'test/config.js',
        {pattern: 'src/**/*.js', included: false},
        'test/test_data.js',
        'test/test_utils.js',
        {pattern: 'test/**/*_test.js', included: false},
        'test/test_main.js',
    ],

    // List of files to exclude.
    exclude: [
    ],

    // Test results reporter to use.
    // Possible values: 'dots', 'progress', 'junit', 'growl', 'coverage'.
    reporters: ['progress', 'coverage', 'junit'],

    // Source files to generate a coverage report for.
    // (Do not include tests or libraries.
    // These files will be instrumented by Istanbul.)
    preprocessors: {
        'src/**/*.js': ['coverage']
    },

    // Coverage configuration
    coverageReporter: {
        type: 'html',
        dir: 'coverage/'
    },
        
    // JUnit reporter configuration.
    junitReporter: {
        outputFile: 'test-results.xml'
    },

    // Web server port.
    port: 9876,

    // Enable/disable colours in the output (reporters and logs).
    colors: true,

    // Level of logging.
    // Possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG.
    logLevel: config.LOG_INFO,

    // Enable/disable watching file and executing tests whenever any file changes.
    autoWatch: true,

    // Start these browsers, currently available:
    // - Chrome
    // - ChromeCanary
    // - Firefox
    // - Opera (has to be installed with `npm install karma-opera-launcher`)
    // - Safari (only Mac; has to be installed with `npm install karma-safari-launcher`)
    // - PhantomJS
    // - IE (only Windows; has to be installed with `npm install karma-ie-launcher`)
    browsers: ['PhantomJS', 'Firefox', 'Chrome'],

    // If browser does not capture in given timeout [ms], kill it
    captureTimeout: 120000,
    browserNoActivityTimeout: 120000,

    // Continuous Integration mode.
    // If true, it capture browsers, run tests and exit.
    singleRun: false
  });
};
