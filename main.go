package main

import (
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	port := 10000

	done := make(chan bool, 1)

	// Make 2 hosts
	host := makeRandomNode(port, done)

	log.Printf("host ID %s\n", host.ID())

	run(host, done)
}

// helper method - create a lib-p2p host to listen on a port
func makeRandomNode(port int, done chan bool) *Node {
	// Ignoring most errors for brevity
	// See echo example for more details and better implementation
	priv, _, _ := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	listen, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	host, _ := libp2p.New(
		libp2p.ListenAddrs(listen),
		libp2p.Identity(priv),
	)

	return NewNode(host, done)
}

func run(host *Node, done <-chan bool) {
	// connect peers
	addressList := []string{}
	var multiaddrs []ma.Multiaddr
	// Turn the destination into a multiaddr.
	for _, addr := range addressList {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			log.Println(err)
			return
		}
		multiaddrs = append(multiaddrs, maddr)
	}

	host.Peerstore().AddAddrs(host.ID(), multiaddrs, peerstore.PermanentAddrTTL)
	//h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), peerstore.PermanentAddrTTL)

	// send messages using the protocols
	//h1.Ping(h2.Host)
	//h1.Echo(h2.Host)

	// block until all responses have been processed
	for i := 0; i < 8; i++ {
		<-done
	}
}
