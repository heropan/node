package service

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/heropan/node/build"
	"github.com/heropan/node/chainreg"
	"github.com/heropan/node/signal"

	"github.com/btcsuite/btcutil"
	"github.com/jessevdk/go-flags"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	DefaultConfigFilename = "node.conf"
	defaultDataDirname    = "data"
	defaultLogLevel       = "info"
	defaultLogDirname     = "logs"
	defaultLogFilename    = "lnd.log"
	defaultPeerPort       = 9000

	defaultMaxLogFiles    = 3
	defaultMaxLogFileSize = 10
)

var (
	// DefaultLndDir is the default directory where lnd tries to find its
	// configuration file and store its data. This is a directory in the
	// user's application data, for example:
	//   C:\Users\<username>\AppData\Local\node on Windows
	//   ~/.node on Linux
	//   ~/Library/Application Support/node on MacOS
	DefaultNodeDir = btcutil.AppDataDir("Node", false)

	// DefaultConfigFile is the default full path of lnd's configuration
	// file.
	DefaultConfigFile = filepath.Join(DefaultNodeDir, DefaultConfigFilename)
	defaultDataDir    = filepath.Join(DefaultNodeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(DefaultNodeDir, defaultLogDirname)
)

type Config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	NodeDir    string `long:"nodedir" description:"The base directory that contains node's data, logs, configuration file, etc."`
	ConfigFile string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir    string `short:"b" long:"datadir" description:"The directory to store node's data within"`

	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	IdentityKey  string   `long:"idkey" description:"Configures libp2p to use the given private key to identify itself."`
	RawListeners []string `long:"listen" description:"Add an \"/network/ip/tcp/port\" to listen for peer connections (default: \"/ip4/127.0.0.1/tcp/9000\")"`
	Listeners    []ma.Multiaddr

	RawPeers []string `long:"peers" description:"This peer will connect to the peers."`
	Peers    []peer.AddrInfo

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <global-level>,<subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	MainNet  bool `long:"mainnet" description:"Use the main network"`
	TestNet3 bool `long:"testnet" description:"Use the test network"`
	SimNet   bool `long:"simnet" description:"Use the simulation test network"`
	RegTest  bool `long:"regtest" description:"Use the regression test network"`

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
		NodeDir:         DefaultNodeDir,
		ConfigFile:      DefaultConfigFile,
		DataDir:         defaultDataDir,
		LogDir:          defaultLogDir,
		MaxLogFiles:     defaultMaxLogFiles,
		MaxLogFileSize:  defaultMaxLogFileSize,
		DebugLevel:      defaultLogLevel,
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

	// If the provided lnd directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	nodeDir := CleanAndExpandPath(cfg.NodeDir)
	if nodeDir != DefaultNodeDir {
		cfg.DataDir = filepath.Join(nodeDir, defaultDataDirname)
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
	// Multiple networks can't be selected simultaneously.  Count
	// number of network flags passed; assign active network params
	// while we're at it.
	numNets := 0
	if cfg.MainNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinMainNetParams
	}
	if cfg.TestNet3 {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinTestNetParams
	}
	if cfg.RegTest {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinRegTestNetParams
	}
	if cfg.SimNet {
		numNets++
		cfg.ActiveNetParams = chainreg.BitcoinSimNetParams
	}
	if numNets > 1 {
		str := "The mainnet, testnet, regtest, and simnet " +
			"params can't be used together -- choose one " +
			"of the four"
		return nil, mkErr(str)
	}
	// We'll now construct the network directory which will be where we
	// store all the data specific to this chain/network.
	cfg.networkDir = filepath.Join(
		cfg.DataDir, NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// Create the lnd directory and all other sub-directories if they don't
	// already exist. This makes sure that directory trees are also created
	// for files that point to outside the lnddir.
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
		cfg.LogDir, NormalizeNetwork(cfg.ActiveNetParams.Name),
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
	// their lnddir, then we should assume they intend to use the config
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
