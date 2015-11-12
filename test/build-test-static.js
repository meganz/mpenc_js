#!/usr/bin/env node

// shim in browser global vars that some libs assume the existence of
navigator = { appName: "nodejs" }; // jshint ignore:line
location = { href: "" }; // jshint ignore:line
crypto = { // jshint ignore:line
    // this is dangerous, only for dev testing. never copy it into real code.
    getRandomValues: function(a) {
        a.forEach(function(v, i, a) { a[i] = 0; });
    }
};

// load our library
var mpenc = require(process.argv[2]);

// debug print our public API
console.log(mpenc);
