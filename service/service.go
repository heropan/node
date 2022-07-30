package service

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heropan/node/nodecfg"
	"github.com/heropan/node/signal"

	"github.com/jessevdk/go-flags"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
)

type Service struct {
	Cfg    *Config
	Done   chan bool
	Node   *Node
	Client *rpcclient.Client
}

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

func showOutput(v interface{}) {
	dataBytes, err := json.Marshal(v)
	if err != nil {
		fmt.Println(err)
		return
	}

	buf := new(bytes.Buffer)
	json.Indent(buf, dataBytes, "", "    ")
	fmt.Println(string(buf.Bytes()))
}

func Main(interceptor signal.Interceptor) {
	cfg, err := LoadConfig(interceptor)
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	done := make(chan bool, 1)

	host, err := makeRandomNode(*cfg, done)
	if err != nil {
		fmt.Printf("make node err: %v\n", err)
		return
	}

	srv := &Service{
		Cfg:  cfg,
		Done: done,
		Node: host,
	}

	// print the node's PeerInfo in multiaddr format
	peerInfo := peer.AddrInfo{
		ID:    host.ID(),
		Addrs: host.Addrs(),
	}
	addrs, err := peer.AddrInfoToP2pAddrs(&peerInfo)
	if err != nil {
		fmt.Printf("format addr info err: %v\n", err)
		return
	}
	srvrLog.Infof("walletname: %v", srv.Cfg.WalletName)
	srvrLog.Infof("network: %v", NormalizeNetwork(cfg.ActiveNetParams.Name))
	srvrLog.Infof("libp2p node address: %s", addrs[0])

	switch cfg.Bitcoin.Node {
	case "bitcoind":
		var bitcoindMode *nodecfg.Bitcoind
		bitcoindMode = cfg.BitcoindMode

		var bitcoindHost string
		if strings.Contains(bitcoindMode.RPCHost, ":") {
			bitcoindHost = bitcoindMode.RPCHost
		} else {
			// The RPC ports specified in chainparams.go assume
			// btcd, which picks a different port so that btcwallet
			// can use the same RPC port as bitcoind. We convert
			// this back to the btcwallet/bitcoind port.
			rpcPort, err := strconv.Atoi(cfg.ActiveNetParams.RPCPort)
			if err != nil {
				fmt.Printf("atoi err")
				return
			}
			rpcPort -= 2
			bitcoindHost = fmt.Sprintf("%v:%d",
				bitcoindMode.RPCHost, rpcPort)
			if cfg.Bitcoin.Active && (cfg.Bitcoin.RegTest || cfg.Bitcoin.SigNet) {

				conn, err := net.Dial("tcp", bitcoindHost)
				if err != nil || conn == nil {
					switch {
					case cfg.Bitcoin.Active && cfg.Bitcoin.RegTest:
						rpcPort = 18443
					case cfg.Bitcoin.Active && cfg.Bitcoin.SigNet:
						rpcPort = 38332
					}
					bitcoindHost = fmt.Sprintf("%v:%d",
						bitcoindMode.RPCHost,
						rpcPort)
				} else {
					conn.Close()
				}
			}
		}

		if srv.Cfg.WalletName != "" {
			bitcoindHost = bitcoindHost + "/wallet/" + srv.Cfg.WalletName
		}

		connCfg := &rpcclient.ConnConfig{
			Host:                 bitcoindHost,
			User:                 bitcoindMode.RPCUser,
			Pass:                 bitcoindMode.RPCPass,
			DisableAutoReconnect: false,
			DisableTLS:           true,
			HTTPPostMode:         true,
		}
		client, err := rpcclient.New(connCfg, nil)
		if err != nil {
			log.Fatal(err)
		}

		srv.Client = client

	case "btcd":
	default:
		fmt.Printf("unknown node type: %s", cfg.Bitcoin.Node)
		return
	}

	run(srv)

	<-interceptor.ShutdownChannel()
}

// helper method - create a lib-p2p host to listen on a port
func makeRandomNode(cfg Config, done chan bool) (*Node, error) {
	// Ignoring most errors for brevity
	// See echo example for more details and better implementation
	var priv crypto.PrivKey
	var err error

	if len(cfg.IdentityKey) == 0 {
		srvrLog.Errorf("no idkey configured")

		priv, _, err = crypto.GenerateKeyPair(crypto.Secp256k1, 256)
		if err != nil {
			srvrLog.Errorf("generate key pair err: %s", err.Error())
			return nil, err
		}

		prvRaw, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			srvrLog.Errorf("get priv key raw err: %s", err.Error())
			return nil, err
		}

		prvStr := crypto.ConfigEncodeKey(prvRaw)
		srvrLog.Errorf("randomly generate one: %s", prvStr)
		return nil, errors.New("configure idkey first")
	} else {
		prvRaw, err := crypto.ConfigDecodeKey(cfg.IdentityKey)
		if err != nil {
			srvrLog.Errorf("decode key err: %s", err.Error())
			return nil, err
		}

		priv, err = crypto.UnmarshalPrivateKey(prvRaw)
		if err != nil {
			srvrLog.Errorf("unmarshal priv key err: %s", err.Error())
			return nil, err
		}
	}

	host, _ := libp2p.New(
		libp2p.ListenAddrs(cfg.Listeners[0]),
		libp2p.Identity(priv),
	)

	return NewNode(host, done), nil
}

func run(srv *Service) {
	for _, p := range srv.Cfg.Peers {
		srv.Node.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.PermanentAddrTTL)
	}

	rpctest(srv.Cfg, srv.Client)
	go pingruntine(srv)
}

// legacyGetBlockRequest constructs and sends a legacy getblock request which
// contains two separate bools to denote verbosity, in contract to a single int
// parameter.
func listWallets(c *rpcclient.Client) ([]string, error) {
	rawMessage, err := c.RawRequest("listwallets", nil)
	if err != nil {
		return []string{}, err
	}

	var result []string
	err = json.Unmarshal(rawMessage, &result)
	if err != nil {
		return []string{}, err
	}

	return result, nil
}

func rpctest(cfg *Config, client *rpcclient.Client) {

	// Get the list of unspent transaction outputs (utxos) that the
	// connected wallet has at least one private key for.
	//unspent, err := client.ListUnspent()
	//if err != nil {
	//	log.Fatal("listunspent err: ", err)
	//}
	//log.Printf("Num unspent outputs (utxos): %d", len(unspent))
	//if len(unspent) > 0 {
	//	log.Printf("First utxo:\n%v", spew.Sdump(unspent[0]))
	//}
	//
	//for _, us := range unspent {
	//	if us.Address == "2MtAwxuEEdsbJGnJvKmowoEfEf9QYHFsPZA" {
	//		log.Printf("====== unspent of ('%s')", us.Address)
	//		showOutput(us)
	//	}
	//}

	wpkh1, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(hexToBytes("0227f08c965311c8bc47c8a72c8df208038bd049d39e6eadc48dc23d136728f308")), cfg.ActiveNetParams.Params)
	pks1, _ := txscript.PayToAddrScript(wpkh1)
	addr1, _ := btcutil.NewAddressScriptHash(pks1, cfg.ActiveNetParams.Params)
	log.Printf("addr1: %s", addr1.EncodeAddress())

	wpkh2, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(hexToBytes("02ba135d6eb72ca28b366c5806dd4a17820742c92ceb75de503d7c7f91a9cbdc8d")), cfg.ActiveNetParams.Params)
	pks2, _ := txscript.PayToAddrScript(wpkh2)
	addr2, _ := btcutil.NewAddressScriptHash(pks2, cfg.ActiveNetParams.Params)
	log.Printf("addr2: %s", addr2.EncodeAddress())

	wpkh3, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(hexToBytes("0301263387b72889bdf6f0287ebf114f9099509b0cd3a72cabae3ab4d50b42c275")), cfg.ActiveNetParams.Params)
	pks3, _ := txscript.PayToAddrScript(wpkh3)
	addr3, _ := btcutil.NewAddressScriptHash(pks3, cfg.ActiveNetParams.Params)
	log.Printf("addr3: %s", addr3.EncodeAddress())

	var addresses []btcutil.Address
	addr, _ := btcutil.NewAddressPubKey(hexToBytes("0227f08c965311c8bc47c8a72c8df208038bd049d39e6eadc48dc23d136728f308"), cfg.ActiveNetParams.Params)
	addresses = append(addresses, addr)
	addr, _ = btcutil.NewAddressPubKey(hexToBytes("02ba135d6eb72ca28b366c5806dd4a17820742c92ceb75de503d7c7f91a9cbdc8d"), cfg.ActiveNetParams.Params)
	addresses = append(addresses, addr)
	addr, _ = btcutil.NewAddressPubKey(hexToBytes("0301263387b72889bdf6f0287ebf114f9099509b0cd3a72cabae3ab4d50b42c275"), cfg.ActiveNetParams.Params)
	addresses = append(addresses, addr)

	multisigResp, err := client.CreateMultisig(2, addresses)
	if err != nil {
		fmt.Printf("CreateMultisig err: %s", err.Error())
		return
	}
	showOutput(multisigResp)
	multiAddress, err := btcutil.DecodeAddress(multisigResp.Address, cfg.ActiveNetParams.Params)
	if err != nil {
		log.Fatalf("DecodeAddress err: %v", err)
	}

	addr1Info, err := client.GetAddressInfo(addr1.EncodeAddress())
	if err != nil {
		fmt.Printf("rpc getaddrinfo %s err: %s", "2MsijEHJpaHmrVkh2TuRNn5kuiVEpMRfHpM", err.Error())
		return
	}
	showOutput(addr1Info)

	multiAddrInfo, err := client.GetAddressInfo(multiAddress.EncodeAddress())
	if err != nil {
		fmt.Printf("rpc getaddrinfo %s err: %s", "2MsijEHJpaHmrVkh2TuRNn5kuiVEpMRfHpM", err.Error())
		return
	}
	showOutput(multiAddrInfo)

	multiAddr, err := btcutil.DecodeAddress(multisigResp.Address, cfg.ActiveNetParams.Params)
	if err != nil {
		log.Fatal("DecodeAddress err: ", err)
		return
	}

	if err = client.ImportAddress(multisigResp.Address); err != nil {
		log.Fatal("ImportAddress err ", err)
	}

	unspents, err := client.ListUnspentMinMaxAddresses(0, 10, []btcutil.Address{multiAddr})
	if err != nil {
		log.Fatal("ListUnspentMinMaxAddresses err: ", err)
	}
	log.Printf("utxo of (%s): ", multiAddr.String())
	showOutput(unspents)

	sendAmount, err := btcutil.NewAmount(0.1)
	if err != nil {
		log.Fatalf("NewAmount err: %v", err)
	}

	totalBalance, err := btcutil.NewAmount(0)
	if err != nil {
		log.Fatalf("NewAmount err: %v", err)
	}

	fee, err := btcutil.NewAmount(0.0001)
	if err != nil {
		log.Fatalf("NewAmount err: %v", err)
	}

	var inputs []btcjson.TransactionInput
	for _, unspent := range unspents {
		input := btcjson.TransactionInput{
			Txid: unspent.TxID,
			Vout: unspent.Vout,
		}
		inputs = append(inputs, input)
		utxoAmount, err := btcutil.NewAmount(unspent.Amount)
		if err != nil {
			log.Fatalf("NewAmount err: %v", err)
		}
		totalBalance += utxoAmount
	}
	log.Printf("totalBalance: %v", totalBalance)

	amounts := map[btcutil.Address]btcutil.Amount{
		addr2:        sendAmount,
		multiAddress: totalBalance - sendAmount - fee,
	}

	// transfer 0.1 BTC to and change back to self address
	tx, err := client.CreateRawTransaction(inputs, amounts, nil)
	if err != nil {
		log.Fatalf("CreateRawTransaction err %v", err)
	}

	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		log.Fatalf("tx serialize err: %v", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())
	log.Printf("txHex: %s", txHex)

	txDecoded, err := client.DecodeRawTransaction(buf.Bytes())
	if err != nil {
		log.Fatalf("decode tx err: %v", err)
	}
	showOutput(txDecoded)
}

func pingruntine(srv *Service) {
	for {
		for _, p := range srv.Cfg.Peers {
			srv.Node.Ping(p.ID)
		}

		for i := 0; i < 2; i++ {
			<-srv.Done
		}
		time.Sleep(5000 * time.Millisecond)
	}
}
