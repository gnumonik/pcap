module Main where

import qualified Control.Concurrent as C
import qualified Control.Concurrent.Async as C
import           Control.Monad (when, void)
import qualified Data.ByteString as BS
import           Foreign (peekArray)
import qualified Network.Pcap as P
import qualified System.Console.GetOpt as G
import           System.Environment (getArgs)

usage :: String -> IO void
usage errMsg = error $ G.usageInfo header optsSpec
    where
    header = unlines
        [ errMsg
        , ""
        , "usage: pcap-example [OPTIONS] (live NUM IFACE | read NUM FILE | dump NUM IFACE FILE)"
        , ""
        , "* live NUM IFACE: live capture NUM packets on IFACE and summarize"
        , "  the packets."
        , ""
        , "* read NUM FILE: read (up to) NUM captured from FILE and summarize"
        , "  the packets."
        , ""
        , "* dump NUM IFACE FILE: live capture NUM packets on IFACE and save"
        , "  the packets to FILE."
        , ""
        , "A NUM value of 0 or -1 means to read packets forever, or until "
        , "end-of-file in case of reading from a file."
        , ""
        , "An IFACE value of 'any' means to capture on all interfaces."
        , ""
        , "Options:"
        ]

main :: IO ()
main = do
    cmdArgs <- getArgs
    (opts, num, cmd, args) <- parseArgs cmdArgs
    cmd opts num args

----------------------------------------------------------------
-- Options
--
-- We interpret flags as option transformers, as in this example:
-- http://hackage.haskell.org/package/base-4.10.0.0/docs/System-Console-GetOpt.html#g:4

-- | Parse command line arguments.
parseArgs :: [String] -> IO (Opts, Int, Cmd, [String])
parseArgs cmdArgs = do
    let (optTransforms, args, errs) = G.getOpt G.Permute optsSpec cmdArgs
    when (not $ null errs) $ do
        usage $ "Bad options: "++show errs
    when (length args < 2) $ do
        usage "Not enough args!"
    let cmdS:numS:args' = args
    let num = read numS :: Int
    cmd <- case cmdS of
        "live" -> return live
        "read" -> return read'
        "dump" -> return dump
        _ -> usage $ "Unknown command: "++cmdS
    let opts = foldr id defaultOpts optTransforms
    return (opts, num, cmd, args')

data Opts = Opts { timeLimit :: Maybe Int }
     deriving (Show)

defaultOpts :: Opts
defaultOpts = Opts { timeLimit = Nothing }

type OptsTransform = Opts -> Opts

-- | The specification of all the options.
optsSpec :: [G.OptDescr OptsTransform]
optsSpec = [ G.Option ['t'] ["time"] (G.ReqArg parseTime "SECONDS")
            "Time limit for capture in whole seconds." ]

-- | Parse the time option.
parseTime :: String -> OptsTransform
parseTime timeS opts = opts { timeLimit = Just $ read timeS }

----------------------------------------------------------------
-- Commands

type Cmd = Opts -> Int -> [String] -> IO ()

-- | Summarize a live capture on the given interface.
live :: Cmd
live opts numPktsToRead [iface] = do
    ph <- P.openLive iface 100 False 10000
    capture opts ph numPktsToRead printIt
live _ _ _ = usage "live: wrong number of args!"

-- | Summarize a capture read from disk.
read' :: Cmd
read' opts numPktsToRead [file] = do
    ph <- P.openOffline file
    capture opts ph numPktsToRead printIt
read' _ _ _ = usage "read: wrong number of args!"

-- | Dump a live capture to a file.
dump :: Cmd
dump opts numPktsToRead [iface, file] = do
    ph <- P.openLive iface 100 False 10000
    dh <- P.openDump ph file
    capture opts ph numPktsToRead (P.dump dh)
dump _ _ _ = usage "dump: wrong number of args!"

----------------------------------------------------------------
-- Helpers

-- | Capture and process packets using the given callback.
--
-- Prints the data link type, which determines the binary format of
-- the raw packet payloads.
--
-- Runs the capture in a separate thread so that the program will
-- respond to Ctrl-C. Optionally breaks the capture loop after a
-- time limit.
capture :: Opts -> P.PcapHandle -> Int -> P.Callback -> IO ()
capture opts ph numPktsToRead callback = do
    link <- P.datalink ph
    putStrLn $ "Data link type: "++show link
    -- Running the capture in a different thread (and compiling with
    -- @-threaded@!) allows the program to be interrupted by
    -- Ctrl-C.
    --
    -- But be careful. If you don't care about 'breakLoop', and just
    -- want Ctrl-C to work, then this works:
    --
    -- > C.async (P.loop ph numPktsToRead callback) >>= C.wait
    --
    -- But this doesn't:
    --
    -- > C.withAsync (capture ph numPktsToRead (P.dump dh)) C.wait
    --
    -- !?!?!?
    a <- C.async (P.loop ph numPktsToRead callback)
    case timeLimit opts of
        Nothing -> return ()
        Just secs -> void $ C.async $ do
            let microSecs = secs * 1000000
            C.threadDelay microSecs
            P.breakLoop ph
    C.wait a

-- | Print information about a packet.
printIt :: P.Callback
printIt ph bytep = do
    -- We could of course use the 'P.loopBS' interface instead, to
    -- avoid doing our own bytestring conversion here.
    bytes <- peekArray (fromIntegral (P.hdrCaptureLength ph)) bytep
    print ph
    print $ BS.pack bytes
