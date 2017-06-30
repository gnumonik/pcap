module Main where

import qualified Data.ByteString as BS
import           Foreign
import qualified Network.Pcap as P
import           System.Environment (getArgs)

usage :: String -> IO ()
usage errMsg = error $ unlines
    [ errMsg
    , ""
    , "usage: pcap-exampe (live NUM IFACE | file NUM FILE | dump NUM IFACE FILE)"
    , ""
    , "* live NUM IFACE: live capture NUM packets on IFACE and summarize"
    , "  the packets."
    , ""
    , "* file NUM FILE: read (up to) NUM captured from FILE and summarize"
    , "  the packets."
    , ""
    , "* dump NUM IFACE FILE: live capture NUM packets on IFACE and save"
    , "  the packets to FILE."
    , ""
    , "A NUM value of 0 or -1 means to read packets forever, or until "
    , "end-of-file in case of reading from a file."
    , ""
    , "An IFACE value of 'any' means to capture on all interfaces."
    ]

main :: IO ()
main = do
    cmdArgs <- getArgs
    if length cmdArgs < 2
        then usage "Not enough args!"
        else do
        let cmd:numS:args = cmdArgs
        let num = read numS :: Int
        case cmd of
            "live" -> live num args
            "read" -> read' num args
            "dump" -> dump num args
            _ -> usage $ "Unknown command: "++cmd

-- | Summarize a live capture on the given interface.
live :: Int -> [String] -> IO ()
live numPktsToRead [iface] = do
    ph <- P.openLive iface 100 False 10000
    capture ph numPktsToRead printIt
live _ _ = usage "live: wrong number of args!"

-- | Summarize a capture read from disk.
read' :: Int -> [String] -> IO ()
read' numPktsToRead [file] = do
    ph <- P.openOffline file
    capture ph numPktsToRead printIt
read' _ _ = usage "read: wrong number of args!"

-- | Dump a live capture to a file.
dump :: Int -> [String] -> IO ()
dump numPktsToRead [iface, file] = do
    ph <- P.openLive iface 100 False 10000
    dh <- P.openDump ph file
    capture ph numPktsToRead (P.dump dh)
dump _ _ = usage "dump: wrong number of args!"

-- | Capture and process packets using the given callback.
--
-- Prints the data link type, which determines the binary format of
-- the raw packet payloads.
capture :: P.PcapHandle -> Int -> P.Callback -> IO ()
capture ph numPktsToRead callback = do
    link <- P.datalink ph
    putStrLn $ "Data link type: "++show link
    P.loop ph numPktsToRead callback

printIt :: P.Callback
printIt ph bytep = do
    -- We could of course use the 'P.loopBS' interface instead, to
    -- avoid doing our own bytestring conversion here.
    bytes <- peekArray (fromIntegral (P.hdrCaptureLength ph)) bytep
    print $ BS.pack bytes
