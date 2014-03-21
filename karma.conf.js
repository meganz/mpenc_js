// Karma configuration
// Generated on Thu Jan 30 2014 15:59:20 GMT+1300 (NZDT)

module.exports = function(config) {
  config.set({
    // base path, that will be used to resolve files and exclude
    basePath: '',

    // frameworks to use
    frameworks: ['mocha', 'chai', 'sinon'],

    // list of files / patterns to load in the browser
    files: [
      // Dependency-based load order of lib/ modules.
      'lib/sjcl.js',
      'lib/curve255.js',
      'lib/jsbn.js',
      'lib/jsbn2.js',
      'lib/sha512.js',
      'lib/djbec.js',
      'lib/rsa.js',
      
      //{pattern: 'lib/*.js', included: true},
      'src/mpenc.js',
      {pattern: 'src/*.js', included: true},
      'test/test_data.js',
      {pattern: 'test/*.js', included: true}
    ],

    // list of files to exclude
    exclude: [
    ],

    // test results reporter to use
    // possible values: 'dots', 'progress', 'junit', 'growl', 'coverage'
    reporters: ['progress', 'coverage'],

    // Source files to generate a coverage report for.
    // (Do not include tests or libraries.
    // These files will be instrumented by Istanbul.)
    preprocessors: {
         'src/*.js': ['coverage']
     },

// Coverage configuration
    coverageReporter: {
        type: 'html',
        dir: 'coverage/' 
    },
    
    // web server port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,

    // Start these browsers, currently available:
    // - Chrome
    // - ChromeCanary
    // - Firefox
    // - Opera (has to be installed with `npm install karma-opera-launcher`)
    // - Safari (only Mac; has to be installed with `npm install karma-safari-launcher`)
    // - PhantomJS
    // - IE (only Windows; has to be installed with `npm install karma-ie-launcher`)
    browsers: ['Firefox', 'Chrome'],

    // If browser does not capture in given timeout [ms], kill it
    captureTimeout: 60000,

    // Continuous Integration mode
    // if true, it capture browsers, run tests and exit
    singleRun: false
  });
};
 
