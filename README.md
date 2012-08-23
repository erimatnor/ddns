Dynamic DNS library (DDNS)
==========================

This is a small C-library for interacting with dynamic DNS (DDNS)
services. The goal is to support multiple backend DDNS protocols using
a single frontend API.

Requirements
------------

* autotools
* csocket library (github.com/erimatnor/csocket)

Install
-------

```
autoreconf --install
./configure 
make
make install
```

Contact
-------

Erik Nordström <erik.nordstrom@gmail.com>
