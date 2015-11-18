This is an implementation of the Multi-Party Encrypted Messaging Protocol, by
MEGA limited, as a JavaScript library. Its main purpose is to be used within a
JavaScript web application that provides end-to-end secure group messaging.

## Documentation

If you are reading this as a web page, you probably want:

- [API documentation](../api/module-mpenc.html) - for clients that wish
  to use this library in their applications.
- [developer docs](../dev/module-mpenc.html) - for developers that wish
  to contribute patches or new features to this library.

## Test dependencies

Using your system package manager (e.g. Homebrew or Debian aptitude), install
PhantomJS *or* `xvfb` and a browser (Firefox or Chrome), *or* both. Both setups
work on headless machines such as a CI or build server, but `xvfb` + a browser
will pull in more libraries than PhantomJS. But in some cases, the tests run
even quicker than PhantomJS.

If you have installed Firefox extensions on a system-wide basis that interferes
with tests (e.g. NoScript), you can set `PATH="$PWD/contrib:$PATH"` to work
around that.

For more details about using PhantomJS 2, see [below](#PhantomJS_2).

## Building

To build this library, in the top-level repository directory run:

    $ make all

This will download dependencis from `npm`, run unit tests, build documentation,
build a dynamically-linked `mpenc.js` in the top-level repository directory, a
statically-linked `mpenc-static.js` in `build/`, and then run some basic tests
on both of these to make sure linking worked correctly.

See `Makefile` for more fine-grained targets to run. One target of interest is
`test-browser`, which keeps the browser open to watch changes you make to the
source files, and re-run affected tests automatically.

Both the static- and dynamically-linked forms may be loaded as a AMD module
(e.g. with RequireJS), a CommonJS module (e.g. in NodeJS), or directly using a
`<script>` tag in which case the entry point will be made accessible via the
global `mpenc` variable. The difference is that with the dynamic form, you also
need to load the other dependencies yourself - see `package.json` for details.

<a name="PhantomJS_2"></a>
## PhantomJS 2

You can either:

Install PhantomJS 2 for your entire system. This is the easiest option, and
when completed should make everything else "just work".

- Debian/Ubuntu versioned around 2015-11: install `phantomjs` from [this APT
  repo](https://people.debian.org/~infinity0/apt/)
- Mac OS X: `brew install phantomjs`

Install PhantomJS 2 to a custom location, e.g. your home directory. This is
more fiddly, and you will need to set the `PHANTOMJS_BIN` envvar when running
our tests. However it should work even if your system is not listed in the
options above.

- Linux: Download and extract one of the packages from [this github
  repo](https://github.com/bprodoehl/phantomjs/releases/), not forgetting to
  install the dependencies first.
- Windows / Mac OS X:
  - Download and extract directly from [PhantomJS
    developers] (http://phantomjs.org/download.html), or
  - `npm install phantomjs2` - this currently [doesn't work on
    Linux](https://github.com/zeevl/phantomjs2/pull/3)
