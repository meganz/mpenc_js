var requirejs_config_mpenc =
({
    paths: {
        "curve255": "../lib/curve255",
        "djbec": "../lib/djbec",
//        "fdjbec": "../lib/fdjbec",
        "jsbn": "../lib/jsbn",
        "jsbn2": "../lib/jsbn2",
        "jsSHA": "../lib/sha512",
        "rsa": "../lib/rsa",
        "sjcl": "../lib/sjcl",
    },
    shim: {
        // dependencies that we use directly need to be added here
        "curve255": {
            exports: "curve255",
            init: function() {
                this.curve255 = {
                    curve25519: curve25519,
                    base32decode: c255lbase32decode,
                    base32encode: c255lbase32encode,
                };
            },
        },
        "djbec": {
            deps: ["jsSHA", "jsbn", "jsbn2"],
            exports: "djbec",
            init: function(jsSHA, jsbn, jsbn2) {
                // djbec refers to a global "jsSHA" variable, so define it here
                this.jsSHA = jsSHA;
                this.djbec = djbec;
            },
        },
//        "fdjbec": {
//            deps: ["jsSHA", "jsbn", "jsbn2", "curve255"],
//            exports: "fdjbec",
//            init: function(jsSHA, jsbn, jsbn2) {
//                // fast-djbec refers to a global "jsSHA" variable, so define it here
//                this.jsSHA = jsSHA;
//                // fast-djbec refers to a global "load" function, so define it here
//                this.load = function() { };
//                this.fdjbec = fdjbec;
//            },
//        },
        "rsa": {
            exports: "rsa",
            init: function() {
                return this.rsa = {
                    RSAencrypt: RSAencrypt,
                    RSAdecrypt: RSAdecrypt,
                };
            },
        },
        "sjcl": {
            exports: "sjcl",
            init: function() {
                this.sjcl = sjcl;
            },
        },
    },
})
