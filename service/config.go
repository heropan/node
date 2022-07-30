package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/heropan/node/build"
	"github.com/heropan/node/chainreg"
	"github.com/heropan/node/nodecfg"
	"github.com/heropan/node/signal"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/jessevdk/go-flags"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	DefaultConfigFilename  = "node.conf"
	defaultDataDirname     = "data"
	defaultChainSubDirname = "chain"
	defaultLogLevel        = "info"
	defaultLogDirname      = "logs"
	defaultLogFilename     = "node.log"
	defaultRPCPort         = 10009
	defaultPeerPort        = 9000
	defaultRPCHost         = "localhost"

	defaultMaxLogFiles    = 3
	defaultMaxLogFileSize = 10
)

var (
	// DefaultNodeDir is the default directory where node tries to find its
	// configuration file and store its data. This is a directory in the
	// user's application data, for example:
	//   C:\Users\<username>\AppData\Local\node on Windows
	//   ~/.node on Linux
	//   ~/Library/Application Support/node on MacOS
	DefaultNodeDir = btcutil.AppDataDir("Node", false)

	// DefaultConfigFile is the default full path of node's configuration
	// file.
	DefaultConfigFile = filepath.Join(DefaultNodeDir, DefaultConfigFilename)
	defaultDataDir    = filepath.Join(DefaultNodeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(DefaultNodeDir, defaultLogDirname)

	defaultBtcdDir         = btcutil.AppDataDir("btcd", false)
	defaultBtcdRPCCertFile = filepath.Join(defaultBtcdDir, "rpc.cert")

	defaultBitcoindDir = btcutil.AppDataDir("bitcoin", false)

	// bitcoindEsimateModes defines all the legal values for bitcoind's
	// estimatesmartfee RPC call.
	defaultBitcoindEstimateMode = "CONSERVATIVE"
	bitcoindEstimateModes       = [2]string{"ECONOMICAL", defaultBitcoindEstimateMode}

	defaultPrunedNodeMaxPeers = 4
)

type Config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	NodeDir    string `long:"nodedir" description:"The base directory that contains node's data, logs, configuration file, etc."`
	ConfigFile string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir    string `short:"b" long:"datadir" description:"The directory to store node's data within"`

	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	WalletName   string   `short:"w" long:"walletname" description:"Send RPC for non-default wallet on RPC server (needs to exactly match corresponding -wallet option passed to bitcoind). This changes the RPC endpoint used, e.g. http://127.0.0.1:8332/wallet/<walletname>"`
	IdentityKey  string   `long:"idkey" description:"Configures libp2p to use the given private key to identify itself."`
	RawListeners []string `long:"listen" description:"Add an \"/network/ip/tcp/port\" to listen for peer connections (default: \"/ip4/127.0.0.1/tcp/9000\")"`
	Listeners    []ma.Multiaddr

	RawPeers []string `long:"peers" description:"This peer will connect to the peers."`
	Peers    []peer.AddrInfo

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <global-level>,<subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	Bitcoin      *nodecfg.Chain    `group:"Bitcoin" namespace:"bitcoin"`
	BtcdMode     *nodecfg.Btcd     `group:"btcd" namespace:"btcd"`
	BitcoindMode *nodecfg.Bitcoind `group:"bitcoind" namespace:"bitcoind"`

	// LogWriter is the root logger that all of the daemon's subloggers are
	// hooked up to.
	LogWriter *build.RotatingLogWriter

	// networkDir is the path to the directory of the currently active
	// network. This path will hold the files related to each different
	// network.
	networkDir string

	// ActiveNetParams contains parameters of the target chain.
	ActiveNetParams chainreg.BitcoinNetParams
}

func DefaultConfig() Config {
	return Config{
		NodeDir:        DefaultNodeDir,
		ConfigFile:     DefaultConfigFile,
		DataDir:        defaultDataDir,
		LogDir:         defaultLogDir,
		MaxLogFiles:    defaultMaxLogFiles,
		MaxLogFileSize: defaultMaxLogFileSize,
		DebugLevel:     defaultLogLevel,
		Bitcoin: &nodecfg.Chain{
			Node: "btcd",
		},
		BtcdMode: &nodecfg.Btcd{
			Dir:     defaultBtcdDir,
			RPCHost: defaultRPCHost,
			RPCCert: defaultBtcdRPCCertFile,
		},
		BitcoindMode: &nodecfg.Bitcoind{
			Dir:                defaultBitcoindDir,
			RPCHost:            defaultRPCHost,
			EstimateMode:       defaultBitcoindEstimateMode,
			PrunedNodeMaxPeers: defaultPrunedNodeMaxPeers,
		},
		LogWriter:       build.NewRotatingLogWriter(),
		ActiveNetParams: chainreg.BitcoinTestNetParams,
	}
}

// usageError is an error type that signals a problem with the supplied flags.
type usageError struct {
	err error
}

// Error returns the error string.
//
// NOTE: This is part of the error interface.
func (u *usageError) Error() string {
	return u.err.Error()
}

// ValidateConfig check the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func ValidateConfig(cfg Config, interceptor signal.Interceptor, fileParser, flagParser *flags.Parser) (*Config, error) {

	// If the provided node directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	nodeDir := CleanAndExpandPath(cfg.NodeDir)
	if nodeDir != DefaultNodeDir {
		cfg.DataDir = filepath.Join(nodeDir, defaultDataDirname)
		cfg.LogDir = filepath.Join(nodeDir, defaultLogDirname)
	}

	srvrLog.Infof("node dir: %v", nodeDir)

	funcName := "ValidateConfig"
	mkErr := func(format string, args ...interface{}) error {
		return fmt.Errorf(funcName+": "+format, args...)
	}
	makeDirectory := func(dir string) error {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			// Show a nicer error message if it's because a symlink
			// is linked to a directory that does not exist
			// (probably because it's not mounted).
			if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
				link, lerr := os.Readlink(e.Path)
				if lerr == nil {
					str := "is symlink %s -> %s mounted?"
					err = fmt.Errorf(str, e.Path, link)
				}
			}

			str := "Failed to create node directory '%s': %v"
			return mkErr(str, dir, err)
		}

		return nil
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.DataDir = CleanAndExpandPath(cfg.DataDir)
	cfg.LogDir = CleanAndExpandPath(cfg.LogDir)
	cfg.BtcdMode.Dir = CleanAndExpandPath(cfg.BtcdMode.Dir)
	cfg.BitcoindMode.Dir = CleanAndExpandPath(cfg.BitcoindMode.Dir)

	// Bitcoin must be active.
	if !cfg.Bitcoin.Active {
		return nil, mkErr("bitcoin.active must be set to 1 (true)")
	}
	// Multiple networks can't be selected simultaneously.  Count
	// number of network flags passed; assign active network params
	// while we're at it.
	numNets := 0
	if cfg.Bitcoin.MainNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinMainNetParams
	}
	if cfg.Bitcoin.TestNet3 {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinTestNetParams
	}
	if cfg.Bitcoin.RegTest {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinRegTestNetParams
	}
	if cfg.Bitcoin.SimNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinSimNetParams
	}
	if cfg.Bitcoin.SigNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinSigNetParams

		// Let the user overwrite the default signet parameters.
		// The challenge defines the actual signet network to
		// join and the seed nodes are needed for network
		// discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.Bitcoin.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(
				cfg.Bitcoin.SigNetChallenge,
			)
			if err != nil {
				return nil, mkErr("Invalid "+
					"signet challenge, hex decode "+
					"failed: %v", err)
			}
			sigNetChallenge = challenge
		}

		if len(cfg.Bitcoin.SigNetSeedNode) > 0 {
			sigNetSeeds = make([]chaincfg.DNSSeed, len(
				cfg.Bitcoin.SigNetSeedNode,
			))
			for idx, seed := range cfg.Bitcoin.SigNetSeedNode {
				sigNetSeeds[idx] = chaincfg.DNSSeed{
					Host:         seed,
					HasFiltering: false,
				}
			}
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		cfg.ActiveNetParams.Params = &chainParams
	}
	if numNets > 1 {
		str := "The mainnet, testnet, regtest, and simnet " +
			"params can't be used together -- choose one " +
			"of the four"
		return nil, mkErr(str)
	}

	// The target network must be provided, otherwise, we won't
	// know how to initialize the daemon.
	if numNets == 0 {
		str := "either --bitcoin.mainnet, or bitcoin.testnet," +
			"bitcoin.simnet, or bitcoin.regtest " +
			"must be specified"
		return nil, mkErr(str)
	}

	switch cfg.Bitcoin.Node {
	case "btcd":
		err := parseRPCParams(
			cfg.Bitcoin, cfg.BtcdMode,
			chainreg.BitcoinChain, cfg.ActiveNetParams,
		)
		if err != nil {
			return nil, mkErr("unable to load RPC "+
				"credentials for btcd: %v", err)
		}
	case "bitcoind":
		if cfg.Bitcoin.SimNet {
			return nil, mkErr("bitcoind does not " +
				"support simnet")
		}

		err := parseRPCParams(
			cfg.Bitcoin, cfg.BitcoindMode,
			chainreg.BitcoinChain, cfg.ActiveNetParams,
		)
		if err != nil {
			return nil, mkErr("unable to load RPC "+
				"credentials for bitcoind: %v", err)
		}

	case "nochainbackend":
		// Nothing to configure, we're running without any chain
		// backend whatsoever (pure signing mode).

	default:
		str := "only btcd, bitcoind mode " +
			"supported for bitcoin at this time"
		return nil, mkErr(str)
	}

	cfg.Bitcoin.ChainDir = filepath.Join(
		cfg.DataDir, defaultChainSubDirname,
		chainreg.BitcoinChain.String(),
	)

	// We'll now construct the network directory which will be where we
	// store all the data specific to this chain/network.
	cfg.networkDir = filepath.Join(
		cfg.DataDir, defaultChainSubDirname,
		chainreg.BitcoinChain.String(), NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// Create the node directory and all other sub-directories if they don't
	// already exist. This makes sure that directory trees are also created
	// for files that point to outside the nodedir.
	dirs := []string{
		nodeDir, cfg.DataDir, cfg.networkDir,
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, err
		}
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = filepath.Join(
		cfg.LogDir, chainreg.BitcoinChain.String(), NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// A log writer must be passed in, otherwise we can't function and would
	// run into a panic later on.
	if cfg.LogWriter == nil {
		return nil, mkErr("log writer missing in config")
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems",
			cfg.LogWriter.SupportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	SetupLoggers(cfg.LogWriter, interceptor)
	err := cfg.LogWriter.InitLogRotator(
		filepath.Join(cfg.LogDir, defaultLogFilename),
		cfg.MaxLogFileSize, cfg.MaxLogFiles,
	)
	if err != nil {
		str := "log rotation setup failed: %v"
		return nil, mkErr(str, err)
	}

	// Parse, validate, and set debug log level(s).
	err = build.ParseAndSetDebugLevels(cfg.DebugLevel, cfg.LogWriter)
	if err != nil {
		str := "error parsing debug level: %v"
		return nil, &usageError{mkErr(str, err)}
	}

	// Listen on the default interface/port if no listeners were specified.
	// An empty address string means default interface/address, which on
	// most unix systems is the same as 0.0.0.0. If Tor is active, we
	// default to only listening on localhost for hidden service
	// connections.
	if len(cfg.RawListeners) == 0 {
		addr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", defaultPeerPort)
		cfg.RawListeners = append(cfg.RawListeners, addr)
	}

	// Add default port to all listener addresses if needed and remove
	// duplicate addresses.
	listeners := make([]ma.Multiaddr, 0, len(cfg.RawListeners))
	for _, addr := range cfg.RawListeners {
		listen, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, mkErr("error normalizing p2p listen addrs: %v", err)
		}
		listeners = append(listeners, listen)
	}
	cfg.Listeners = listeners

	peers := make([]peer.AddrInfo, 0, len(cfg.RawPeers))
	for _, p := range cfg.RawPeers {
		srvrLog.Infof("peer: %v", p)
		addrInfo, err := peer.AddrInfoFromString(p)
		if err != nil {
			return nil, mkErr("error convert AddrInfo from string: %v", err)
		}
		peers = append(peers, *addrInfo)
	}
	cfg.Peers = peers

	// All good, return the sanitized result.
	return &cfg, nil
}

func LoadConfig(interceptor signal.Interceptor) (*Config, error) {
	preCfg := DefaultConfig()
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", build.Version(), "commit="+build.Commit)
		os.Exit(0)
	}

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their nodedir, then we should assume they intend to use the config
	// file within it.
	configFileDir := CleanAndExpandPath(preCfg.NodeDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	if configFileDir != DefaultNodeDir {
		if configFilePath == DefaultConfigFile {
			configFilePath = filepath.Join(
				configFileDir, DefaultConfigFilename,
			)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(&cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, err
	}

	// Make sure everything we just loaded makes sense.
	cleanCfg, err := ValidateConfig(
		cfg, interceptor, fileParser, flagParser,
	)
	if usageErr, ok := err.(*usageError); ok {
		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		_, _ = fmt.Fprintln(os.Stderr, usageMessage)
		srvrLog.Warnf("Incorrect usage: %v", usageMessage)

		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		srvrLog.Warnf("Error validating config: %v", usageErr.err)

		return nil, usageErr.err
	}
	if err != nil {
		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		srvrLog.Warnf("Error validating config: %v", err)

		return nil, err
	}
	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		log.Printf("%v", configFileError)
	}

	return cleanCfg, nil
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// NormalizeNetwork returns the common name of a network type used to create
// file paths. This allows differently versioned networks to use the same path.
func NormalizeNetwork(network string) string {
	if strings.HasPrefix(network, "testnet") {
		return "testnet"
	}

	return network
}

func parseRPCParams(cConfig *nodecfg.Chain, nodeConfig interface{},
	net chainreg.ChainCode, netParams chainreg.BitcoinNetParams) error {

	// First, we'll check our node config to make sure the RPC parameters
	// were set correctly. We'll also determine the path to the conf file
	// depending on the backend node.
	var daemonName, confDir, confFile string
	switch conf := nodeConfig.(type) {
	case *nodecfg.Btcd:
		// If both RPCUser and RPCPass are set, we assume those
		// credentials are good to use.
		if conf.RPCUser != "" && conf.RPCPass != "" {
			return nil
		}

		// Get the daemon name for displaying proper errors.
		switch net {
		case chainreg.BitcoinChain:
			daemonName = "btcd"
			confDir = conf.Dir
			confFile = "btcd"
		}

		// If only ONE of RPCUser or RPCPass is set, we assume the
		// user did that unintentionally.
		if conf.RPCUser != "" || conf.RPCPass != "" {
			return fmt.Errorf("please set both or neither of "+
				"%[1]v.rpcuser, %[1]v.rpcpass", daemonName)
		}

	case *nodecfg.Bitcoind:
		// Ensure that if the ZMQ options are set, that they are not
		// equal.
		if conf.ZMQPubRawBlock != "" && conf.ZMQPubRawTx != "" {
			err := checkZMQOptions(
				conf.ZMQPubRawBlock, conf.ZMQPubRawTx,
			)
			if err != nil {
				return err
			}
		}

		// Ensure that if the estimate mode is set, that it is a legal
		// value.
		if conf.EstimateMode != "" {
			err := checkEstimateMode(conf.EstimateMode)
			if err != nil {
				return err
			}
		}

		// If all of RPCUser, RPCPass, ZMQBlockHost, and ZMQTxHost are
		// set, we assume those parameters are good to use.
		if conf.RPCUser != "" && conf.RPCPass != "" &&
			conf.ZMQPubRawBlock != "" && conf.ZMQPubRawTx != "" {
			return nil
		}

		// Get the daemon name for displaying proper errors.
		switch net {
		case chainreg.BitcoinChain:
			daemonName = "bitcoind"
			confDir = conf.Dir
			confFile = "bitcoin"
		}

		// If not all of the parameters are set, we'll assume the user
		// did this unintentionally.
		if conf.RPCUser != "" || conf.RPCPass != "" ||
			conf.ZMQPubRawBlock != "" || conf.ZMQPubRawTx != "" {

			return fmt.Errorf("please set all or none of "+
				"%[1]v.rpcuser, %[1]v.rpcpass, "+
				"%[1]v.zmqpubrawblock, %[1]v.zmqpubrawtx",
				daemonName)
		}
	}

	// If we're in simnet mode, then the running btcd instance won't read
	// the RPC credentials from the configuration. So if node wasn't
	// specified the parameters, then we won't be able to start.
	if cConfig.SimNet {
		return fmt.Errorf("rpcuser and rpcpass must be set to your " +
			"btcd node's RPC parameters for simnet mode")
	}

	fmt.Println("Attempting automatic RPC configuration to " + daemonName)

	confFile = filepath.Join(confDir, fmt.Sprintf("%v.conf", confFile))
	switch cConfig.Node {
	case "btcd", "ltcd":
		nConf := nodeConfig.(*nodecfg.Btcd)
		rpcUser, rpcPass, err := extractBtcdRPCParams(confFile)
		if err != nil {
			return fmt.Errorf("unable to extract RPC credentials: "+
				"%v, cannot start w/o RPC connection", err)
		}
		nConf.RPCUser, nConf.RPCPass = rpcUser, rpcPass

	case "bitcoind", "litecoind":
		nConf := nodeConfig.(*nodecfg.Bitcoind)
		rpcUser, rpcPass, zmqBlockHost, zmqTxHost, err :=
			extractBitcoindRPCParams(netParams.Params.Name, confFile)
		if err != nil {
			return fmt.Errorf("unable to extract RPC credentials: "+
				"%v, cannot start w/o RPC connection", err)
		}
		nConf.RPCUser, nConf.RPCPass = rpcUser, rpcPass
		nConf.ZMQPubRawBlock, nConf.ZMQPubRawTx = zmqBlockHost, zmqTxHost
	}

	fmt.Printf("Automatically obtained %v's RPC credentials\n", daemonName)
	return nil
}

// extractBtcdRPCParams attempts to extract the RPC credentials for an existing
// btcd instance. The passed path is expected to be the location of btcd's
// application data directory on the target system.
func extractBtcdRPCParams(btcdConfigPath string) (string, string, error) {
	// First, we'll open up the btcd configuration file found at the target
	// destination.
	btcdConfigFile, err := os.Open(btcdConfigPath)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = btcdConfigFile.Close() }()

	// With the file open extract the contents of the configuration file so
	// we can attempt to locate the RPC credentials.
	configContents, err := ioutil.ReadAll(btcdConfigFile)
	if err != nil {
		return "", "", err
	}

	// Attempt to locate the RPC user using a regular expression. If we
	// don't have a match for our regular expression then we'll exit with
	// an error.
	rpcUserRegexp, err := regexp.Compile(`(?m)^\s*rpcuser\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", err
	}
	userSubmatches := rpcUserRegexp.FindSubmatch(configContents)
	if userSubmatches == nil {
		return "", "", fmt.Errorf("unable to find rpcuser in config")
	}

	// Similarly, we'll use another regular expression to find the set
	// rpcpass (if any). If we can't find the pass, then we'll exit with an
	// error.
	rpcPassRegexp, err := regexp.Compile(`(?m)^\s*rpcpass\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", err
	}
	passSubmatches := rpcPassRegexp.FindSubmatch(configContents)
	if passSubmatches == nil {
		return "", "", fmt.Errorf("unable to find rpcuser in config")
	}

	return string(userSubmatches[1]), string(passSubmatches[1]), nil
}

// extractBitcoindRPCParams attempts to extract the RPC credentials for an
// existing bitcoind node instance. The passed path is expected to be the
// location of bitcoind's bitcoin.conf on the target system. The routine looks
// for a cookie first, optionally following the datadir configuration option in
// the bitcoin.conf. If it doesn't find one, it looks for rpcuser/rpcpassword.
func extractBitcoindRPCParams(networkName string,
	bitcoindConfigPath string) (string, string, string, string, error) {

	// First, we'll open up the bitcoind configuration file found at the
	// target destination.
	bitcoindConfigFile, err := os.Open(bitcoindConfigPath)
	if err != nil {
		return "", "", "", "", err
	}
	defer func() { _ = bitcoindConfigFile.Close() }()

	// With the file open extract the contents of the configuration file so
	// we can attempt to locate the RPC credentials.
	configContents, err := ioutil.ReadAll(bitcoindConfigFile)
	if err != nil {
		return "", "", "", "", err
	}

	// First, we'll look for the ZMQ hosts providing raw block and raw
	// transaction notifications.
	zmqBlockHostRE, err := regexp.Compile(
		`(?m)^\s*zmqpubrawblock\s*=\s*([^\s]+)`,
	)
	if err != nil {
		return "", "", "", "", err
	}
	zmqBlockHostSubmatches := zmqBlockHostRE.FindSubmatch(configContents)
	if len(zmqBlockHostSubmatches) < 2 {
		return "", "", "", "", fmt.Errorf("unable to find " +
			"zmqpubrawblock in config")
	}
	zmqTxHostRE, err := regexp.Compile(`(?m)^\s*zmqpubrawtx\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", "", err
	}
	zmqTxHostSubmatches := zmqTxHostRE.FindSubmatch(configContents)
	if len(zmqTxHostSubmatches) < 2 {
		return "", "", "", "", errors.New("unable to find zmqpubrawtx " +
			"in config")
	}
	zmqBlockHost := string(zmqBlockHostSubmatches[1])
	zmqTxHost := string(zmqTxHostSubmatches[1])
	if err := checkZMQOptions(zmqBlockHost, zmqTxHost); err != nil {
		return "", "", "", "", err
	}

	// Next, we'll try to find an auth cookie. We need to detect the chain
	// by seeing if one is specified in the configuration file.
	dataDir := filepath.Dir(bitcoindConfigPath)
	dataDirRE, err := regexp.Compile(`(?m)^\s*datadir\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", "", err
	}
	dataDirSubmatches := dataDirRE.FindSubmatch(configContents)
	if dataDirSubmatches != nil {
		dataDir = string(dataDirSubmatches[1])
	}

	chainDir := ""
	switch networkName {
	case "mainnet":
		chainDir = ""
	case "regtest", "testnet3", "signet":
		chainDir = networkName
	default:
		return "", "", "", "", fmt.Errorf("unexpected networkname %v", networkName)
	}

	cookie, err := ioutil.ReadFile(filepath.Join(dataDir, chainDir, ".cookie"))
	if err == nil {
		splitCookie := strings.Split(string(cookie), ":")
		if len(splitCookie) == 2 {
			return splitCookie[0], splitCookie[1], zmqBlockHost,
				zmqTxHost, nil
		}
	}

	// We didn't find a cookie, so we attempt to locate the RPC user using
	// a regular expression. If we  don't have a match for our regular
	// expression then we'll exit with an error.
	rpcUserRegexp, err := regexp.Compile(`(?m)^\s*rpcuser\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", "", err
	}
	userSubmatches := rpcUserRegexp.FindSubmatch(configContents)
	if userSubmatches == nil {
		return "", "", "", "", fmt.Errorf("unable to find rpcuser in " +
			"config")
	}

	// Similarly, we'll use another regular expression to find the set
	// rpcpass (if any). If we can't find the pass, then we'll exit with an
	// error.
	rpcPassRegexp, err := regexp.Compile(`(?m)^\s*rpcpassword\s*=\s*([^\s]+)`)
	if err != nil {
		return "", "", "", "", err
	}
	passSubmatches := rpcPassRegexp.FindSubmatch(configContents)
	if passSubmatches == nil {
		return "", "", "", "", fmt.Errorf("unable to find rpcpassword " +
			"in config")
	}

	return string(userSubmatches[1]), string(passSubmatches[1]),
		zmqBlockHost, zmqTxHost, nil
}

// checkZMQOptions ensures that the provided addresses to use as the hosts for
// ZMQ rawblock and rawtx notifications are different.
func checkZMQOptions(zmqBlockHost, zmqTxHost string) error {
	if zmqBlockHost == zmqTxHost {
		return errors.New("zmqpubrawblock and zmqpubrawtx must be set " +
			"to different addresses")
	}

	return nil
}

// checkEstimateMode ensures that the provided estimate mode is legal.
func checkEstimateMode(estimateMode string) error {
	for _, mode := range bitcoindEstimateModes {
		if estimateMode == mode {
			return nil
		}
	}

	return fmt.Errorf("estimatemode must be one of the following: %v",
		bitcoindEstimateModes[:])
}
