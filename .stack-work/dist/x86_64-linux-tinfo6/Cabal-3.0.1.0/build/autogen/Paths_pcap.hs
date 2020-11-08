{-# LANGUAGE CPP #-}
{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
module Paths_pcap (
    version,
    getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir,
    getDataFileName, getSysconfDir
  ) where

import qualified Control.Exception as Exception
import Data.Version (Version(..))
import System.Environment (getEnv)
import Prelude

#if defined(VERSION_base)

#if MIN_VERSION_base(4,0,0)
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#else
catchIO :: IO a -> (Exception.Exception -> IO a) -> IO a
#endif

#else
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#endif
catchIO = Exception.catch

version :: Version
version = Version [0,5] []
bindir, libdir, dynlibdir, datadir, libexecdir, sysconfdir :: FilePath

bindir     = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/bin"
libdir     = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/lib/x86_64-linux-ghc-8.8.4/pcap-0.5-lnjwKxqOA62aOIRNfSlbs"
dynlibdir  = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/lib/x86_64-linux-ghc-8.8.4"
datadir    = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/share/x86_64-linux-ghc-8.8.4/pcap-0.5"
libexecdir = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/libexec/x86_64-linux-ghc-8.8.4/pcap-0.5"
sysconfdir = "/home/gnumonic/Code/Haskell/pcap/.stack-work/install/x86_64-linux-tinfo6/5c1256c87d5a417786f93618fe73b623283ef6fe0301c0d850c5f20c30ee3730/8.8.4/etc"

getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir, getSysconfDir :: IO FilePath
getBinDir = catchIO (getEnv "pcap_bindir") (\_ -> return bindir)
getLibDir = catchIO (getEnv "pcap_libdir") (\_ -> return libdir)
getDynLibDir = catchIO (getEnv "pcap_dynlibdir") (\_ -> return dynlibdir)
getDataDir = catchIO (getEnv "pcap_datadir") (\_ -> return datadir)
getLibexecDir = catchIO (getEnv "pcap_libexecdir") (\_ -> return libexecdir)
getSysconfDir = catchIO (getEnv "pcap_sysconfdir") (\_ -> return sysconfdir)

getDataFileName :: FilePath -> IO FilePath
getDataFileName name = do
  dir <- getDataDir
  return (dir ++ "/" ++ name)
