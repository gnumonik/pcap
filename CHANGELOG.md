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
- A `Storable` instance for `PktHdr` so that `dump` and `dumpBS` could
  be made usable.
- A not-built-by-default executable `pcap-example` to the
  `pcap.cabal`, with source in `examples/example.hs`. This is expanded
  version of the old example in `test.hs`, which I renamed and moved
  into the `examples` directory to avoid Cabal trying to rebuild the
  `Network.Pcap` modules when compiling the example.
### Changed
- Changed `Network.Pcap.dump` and `Network.Pcap.dumpBS` to take a
  `PktHdr` instead of a `Ptr PktHdr`. This changes their types to
  `Callback` and `CallbackBS`, respectively, so they can now be used
  with the various packet capture functions. Before there was no easy
  way to use them, given the lack of a `Storable PktHdr` instance.
- Changed the types of `Network.Pcap.loop`, and `Network.Pcap.loopBS`
  to return `()` instead of `Int`, since their return codes will
  always be zero.
### Deprecated
### Removed
- Stopped exporting `toPktHdr` because that interface is now exposed
  by `peek` from the `Storable` instance for `PktHdr`.
### Fixed
- Fixed the documentation for `Network.Pcap.Base.loop`,
  `Network.Pcap.loop`, and `Network.Pcap.loopBS`. They don't actually
  return the number of packets read.
### Security

## [0.4.5.2] - 2012-08-29
