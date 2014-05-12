var requirejs_config_mpenc =
({
    paths: {
        "curve255": "../lib/curve255",
        "ed25519": "../lib/ed25519",
        "jsbn": "../lib/jsbn",
        "jsbn2": "../lib/jsbn2",
        "rsa": "../lib/rsa",
    },
    shim: {
        // Dependencies that we use directly need to be added here.
        "curve255": {
            exports: "curve255",
            init: function() {
                this.curve255 = {
                    c255lhexdecode: c255lhexdecode,
                    curve25519: curve25519,
                    base32decode: c255lbase32decode,
                    base32encode: c255lbase32encode,
                };
            },
        },
        "ed25519": {
            deps: ["jsbn", "jsbn2", "curve255"],
            exports: "ed25519",
            init: function(asmCrypto, jsbn, jsbn2) {
                this.ed25519 = ed25519;
            },
        },
        "rsa": {
            exports: "rsa",
            init: function() {
                return this.rsa = {
                    RSAencrypt: RSAencrypt,
                    RSAdecrypt: RSAdecrypt,
                };
            },
        },
    },
})
