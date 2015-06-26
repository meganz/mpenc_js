var requirejs_config_mpenc =
({
    paths: {
        "asmcrypto": "../node_modules/asmcrypto.js/asmcrypto",
        "es6-collections": "../node_modules/es6-collections/es6-collections",
        "jodid25519": "../node_modules/jodid25519/jodid25519",
        "jsbn": "../node_modules/jsbn/index",
        "lru-cache": "../node_modules/lru-cache/lib/lru-cache",
        "megalogger": "../node_modules/megalogger/dist/megaLogger",
        },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmCrypto",
        },
        "jsbn": {
            exports: "BigInteger",
        },
        "jodid25519": {
            deps: ["jsbn", "asmcrypto"],
            exports: "jodid25519",
        },
        "lru-cache": {
            exports: "LRUCache",
        },
    },
})
