This is an implementation of the Multi-Party Encrypted Messaging Protocol, by
MEGA limited, as a JavaScript library. Its main purpose is to be used within a
JavaScript web application that provides end-to-end secure group messaging.

## Documentation

If you are reading this as a web page, you probably want:

- [API documentation](../../doc/api/module-mpenc.html) - for clients that wish
  to use this library in their applications.
- [developer docs](../../doc/dev/module-mpenc.html) - for developers that wish
  to contribute patches or new features to this library.

## Building

To build this library, in the top-level repository directory run:

    $ make all

This will download dependencis from `npm`, run unit tests, build documentation,
build a dynamically-linked `mpenc.js` in the top-level repository directory, a
statically-linked `mpenc-static.js` in `build/`, and then run some basic tests
on both of these to make sure linking worked correctly.

Optionally, you can install `xvfb-run(1)` and a browser (Firefox or Chrome) to
run the tests in a headless environment such as a CI or build server. In some
cases, this is even quicker than using PhantomJS. If you have installed Firefox
extensions on a system-wide basis that interferes with tests (e.g. NoScript),
you can set `PATH="$PWD/contrib:$PATH"` while running them to work around that.

See `Makefile` for more fine-grained targets to run.

Both the static- and dynamically-linked forms may be loaded as a AMD module
(e.g. with RequireJS), a CommonJS module (e.g. in NodeJS), or directly using a
`<script>` tag in which case the entry point will be made accessible via the
global `mpenc` variable. The difference is that with the dynamic form, you also
need to load the other dependencies yourself - see `package.json` for details.
