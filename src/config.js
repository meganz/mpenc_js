var requirejs_config_mpenc =
({
    paths: {
        "jsbn": "../node_modules/jsbn/index",
        "asmcrypto": "../node_modules/asmcrypto.js/asmcrypto",
        "jodid25519": "../node_modules/jodid25519/build/jodid25519-shared",
        },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmcrypto",
            init: function() {
                return asmCrypto;
            },
        },
        "jsbn": {
            exports: "jsbn",
            init: function(jsbn) {
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
