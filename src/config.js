var requirejs_config_mpenc =
({
    paths: {
        "asmcrypto": "../lib/asmcrypto",
        "jodid25519": "../lib/jodid25519-partial",
        "jsbn": "../lib/jsbn",
        "jsbn2": "../lib/jsbn2",
    },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmcrypto",
            init: function() {
                return asmCrypto;
            },
        },
    },
})
