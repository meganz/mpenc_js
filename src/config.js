var requirejs_config_mpenc =
({
    paths: {
        "jsbn1": "../lib/jsbn",
        "jsbn": "../lib/jsbn2",
        "asmcrypto": "../lib/asmcrypto",
        "jodid25519": "../lib/jodid25519-partial",
        },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmcrypto",
            init: function() {
                return asmCrypto;
            },
        },
        "jsbn1": {
            exports: "jsbn1",
        },
        "jsbn": {
            // jsbn2.js is a monkey patch to add methods to BigInteger in jsbn.js.
            // Due to its dependency on jsbn.js, we're mapping jsbn2.js after
            // patching jsbn.js to the jsbn name space.
            deps: ["jsbn1"],
            exports: "jsbn",
            init: function(jsbn1) {
                return {
                    BigInteger: BigInteger,
                };
            },
        },
        "jodid25519": {
            deps: ["jsbn", "asmcrypto"],
            exports: "jodid25519",
        },
    },
})
