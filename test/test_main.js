var tests = [];
for (var file in window.__karma__.files) {
    if (window.__karma__.files.hasOwnProperty(file)) {
        if (/_test\.js$/.test(file)) {
            tests.push(file);
        }
    }
}

requirejs.config({
    // Karma serves files from '/base'
    baseUrl: '/base/src',

    paths: {
        // libs
        'curve255': '../lib/curve255',
        'djbec': '../lib/djbec',
        'jsSHA': '../lib/sha512',
        'rsa': '../lib/rsa',
        'sjcl': '../lib/sjcl',
        // tests
        'sinon': '../node_modules/sinon/lib/sinon',
    },

    shim: {
        // libs
        'curve255': { exports: 'curve255' },
        'djbec': {
            deps: ['jsSHA'],
            exports: 'djbec',
            init: function(jsSHA) {
                // djbec refers to a global "jsSHA" variable, so define it here
                this.jsSHA = jsSHA;
            }},
        'jsSHA': { exports: 'jsSHA' },
        'rsa': {
            exports: 'rsa',
            init: function() {
                return this.rsa = {RSAencrypt: RSAencrypt, RSAdecrypt: RSAdecrypt};
            }},
        'sjcl': { exports: 'sjcl' },
        // tests
        'sinon': { exports: 'sinon' },
        'sinon/assert': { exports: 'sinon.assert' },
        'sinon/sandbox': { exports: 'sinon.sandbox' },
        'sinon/spy': { exports: 'sinon.spy' },
        'sinon/stub': { exports: 'sinon.stub' },
    },

    // ask Require.js to load these files (all our tests)
    deps: tests,

    // start test run, once Require.js is done
    callback: window.__karma__.start
});
