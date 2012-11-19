# signet

A library for signing HTTP request maps.  Only works with string based request
bodies at the moment.

Based on
[Mixlib::Authentication](http://github.com/opscode/mixlib-authentication) via
[JClouds](http://github.com/jclouds/jclouds).

## Usage

The two main methods are `seal` and `unseal`.

## Installation

Available on [clojars](http://clojars.org/signet/signet).

```clj
:dependencies [[signet "0.1.0"]]
```

## License

Copyright (C) 2010, 2012 Hugo Duncan

Licensed under [EPL](http://www.eclipse.org/legal/epl-v10.html)
