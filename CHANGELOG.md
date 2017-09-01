# Changelog

The format of this changelog is based
on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Guidelines for incrementing the package version are described in
the [Haskell Package Versioning Policy]( https://pvp.haskell.org/).

When releasing a new version change `[Unreleased]` to `[<version>] -
<release date>` and copy the template

    ## [Unreleased]
    ### Added
    ### Changed
    ### Deprecated
    ### Removed
    ### Fixed
    ### Security

to create a new changelog section for development of the next release.

## [Unreleased]
### Added
- This changelog!
- Added `Storable` instance for `PktHdr` so that `dump` and `dumpBS` could
  be made usable.
- Added not-built-by-default executable `pcap-example` to the
  `pcap.cabal`, with source in `examples/example.hs`. This is expanded
  version of the old example in `test.hs`, which I renamed and moved
  into the `examples` directory to avoid Cabal trying to rebuild the
  `Network.Pcap` modules when compiling the example.
- Added `Network.Pcap.breakLoop` and `Network.Pcap.Base.breakLoop`,
  exposing the `pcap_breakloop` API for terminating `pcap_loop` and
  `pcap_dispatch` early.
### Changed
- Changed `Network.Pcap.dump` and `Network.Pcap.dumpBS` to take a
  `PktHdr` instead of a `Ptr PktHdr`. This changes their types to
  `Callback` and `CallbackBS`, respectively, so they can now be used
  with the various packet capture functions. Before there was no easy
  way to use them, given the lack of a `Storable PktHdr` instance.
### Deprecated
### Removed
- Stopped exporting `toPktHdr` because that interface is now exposed
  by `peek` from the `Storable` instance for `PktHdr`.
### Fixed
- Fixed the documentation for `Network.Pcap.Base.loop`,
  `Network.Pcap.loop`, and `Network.Pcap.loopBS`. They don't actually
  return the number of packets read.
- Fixed corruption of dump files when killing program with `Ctrl-C`,
  by changing `Network.Pcap.Base.openDump` to use a `ForeignPtr` C
  finalizer that's guaranteed to run.
### Security

## [0.4.5.2] - 2012-08-29
