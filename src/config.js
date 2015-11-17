var requirejs_config_mpenc =
({
    paths: {
        "asmcrypto": "../node_modules/asmcrypto.js/asmcrypto",
        "es6-collections": "../node_modules/es6-collections/es6-collections",
        "lru-cache": "../node_modules/lru-cache/lib/lru-cache",
        "megalogger": "../node_modules/megalogger/dist/megaLogger",
        "promise-polyfill": "../node_modules/promise-polyfill/Promise.min",
        "tweetnacl": "../node_modules/tweetnacl/nacl-fast",
        },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmCrypto",
        },
        "lru-cache": {
            exports: "LRUCache",
        },
        "promise-polyfill": {
            exports: "Promise",
        },
        "tweetnacl": {
            exports: "nacl",
        },
    },
})
