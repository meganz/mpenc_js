var requirejs_config_mpenc =
({
    paths: {
        "asmcrypto": "../lib/asmcrypto",
        "curve255": "../lib/curve255",
        "ed25519": "../lib/ed25519",
        "jsbn": "../lib/jsbn",
        "jsbn2": "../lib/jsbn2",
        "rsa": "../lib/rsa",
    },
    shim: {
        // Dependencies that we use directly need to be added here.
        "asmcrypto": {
            exports: "asmcrypto",
            init: function() {
                return asmCrypto;
            },
        },
        "curve255": {
            exports: "curve255",
            init: function() {
                return {
                    c255lhexdecode: c255lhexdecode,
                    curve25519: curve25519,
                    base32decode: c255lbase32decode,
                    base32encode: c255lbase32encode,
                };
            },
        },
        "ed25519": {
            deps: ["asmcrypto", "jsbn", "jsbn2", "curve255"],
            exports: "ed25519",
            init: function(asmcrypto, jsbn, jsbn2, curve255) {
                return ed25519;
            },
        },
        "rsa": {
            exports: "rsa",
            init: function() {
                return {
                    RSAencrypt: RSAencrypt,
                    RSAdecrypt: RSAdecrypt,
                };
            },
        },
    },
})
