package ipcnameecho

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"log"
)

func init() {
	plugin.Register("ipcnameecho", setup)
	/*
	caddy.RegisterPlugin("ipcnameecho", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
	*/
}

func setup(c *caddy.Controller) error {
	c.Next()
	config, err := newConfigFromDispenser(c.Dispenser)
	if err != nil {
		log.Printf("load config fail\n")
		return plugin.Error("ipcnameecho", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ipcnameecho{Next: next, Config: config, Upstream: upstream.New()}
	})

	return nil
}
