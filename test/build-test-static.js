#!/usr/bin/env node

// shim in browser global vars that some libs assume the existence of
navigator = { appName: "nodejs" }; // jshint ignore:line

// load our library
var mpenc = require(process.argv[2]);

// debug print our public API
console.log(mpenc);
