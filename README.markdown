# Description: 

Updated version of Network.Pcap that supports a few Pcap functions added since the bindings were originally created. This isn't an exhaustive update; I needed to get Immediate Mode working for a project and only added the necessary functions to support that functionality.

New functions are:

pcapCreate :: String -> IO PcapHandle

pcapActivate :: PcapHandle -> IO ()

setImmediateMode :: PcapHandle -> Bool -> IO ()

setSnapLen :: PcapHandle -> Int -> IO ()

setPromisc  :: PcapHandle -> Bool -> IO ()

You'll need a recent libPcap installation. If you're building with Stack, you might have to add a line like: 

extra-lib-dirs: [/path/to/pcap]

to your stack.yaml file. 


## Old Readme: 


# A Haskell wrapper around the C libpcap library

It provides Haskell bindings for most of the libpcap API as of libpcap
version 0.9.7.  The bindings are divided into a very efficient
low-level wrapper, Network.Pcap.Base, and a higher-level module,
Network.Pcap, that's easier to use.


# Installing

To install a stable version from Hackage:

    cabal install pcap

To install from the source repo, you may need to generate autoconf
related files first. For example:

    git clone git://github.com/bos/pcap.git
    cd pcap
    autoconf -i
    autoheader
    cabal install


# Examples

See `examples/example.hs` for an example of live capturing, dumping
captured packets, reading dumped captures from disk, handling Ctrl-C,
and breaking pcap loops. You can build this example by enabling the
`build-the-examples` flag. For example:

    cabal install -f build-the-examples

Or:

    stack install --flag pcap:build-the-examples pcap

# Get involved!

Please report bugs via the
[github issue tracker](https://github.org/bos/pcap).

There's also a [git mirror](http://github.com/bos/pcap):

* `git clone git://github.com/bos/pcap.git`

Master [Mercurial repository](http://bitbucket.org/bos/pcap):

* `hg clone http://bitbucket.org/bos/pcap`

(You can create and contribute changes using either Mercurial or git.)


# Authors

This library was originally written by Gregory Wright, with contributions
by Dominic Steinitz.  The current maintainer is Bryan O'Sullivan,
<bos@serpentine.com>.
