var requirejs_config_mpenc =
({
    paths: {
        "asmcrypto": "../node_modules/asmcrypto.js/asmcrypto",
        "es6-collections": "../node_modules/es6-collections/es6-collections",
        "jodid25519": "../node_modules/jodid25519/jodid25519",
        "jsbn": "../node_modules/jsbn/index",
        "megalogger": "../node_modules/megalogger/dist/megaLogger",
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
                // first case is for plain jsbn, second case is for jsbn node module
                return {
                    BigInteger: (typeof BigInteger !== "undefined") ? BigInteger : module.exports,
                };
            },
        },
        "jodid25519": {
            deps: ["jsbn", "asmcrypto"],
            exports: "jodid25519",
        },
    },
})
