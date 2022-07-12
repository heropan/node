package main

import (
	"fmt"
	"github.com/heropan/node/service"
	"github.com/heropan/node/signal"
	"os"
)

func main() {
	// Hook interceptor for os signals.
	shutdownInterceptor, err := signal.Intercept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	service.Main(shutdownInterceptor)
}
