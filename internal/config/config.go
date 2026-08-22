package config

import "flag"

type Config struct {
	Addr          string
	Store         string
	DBPath        string
	DefaultAction string
	WorkerCount   int
	MaxRulesSync  int
}

func Load() Config {
	c := Config{}
	flag.StringVar(&c.Addr, "addr", ":8080", "HTTP address")
	flag.StringVar(&c.Store, "store", "memory", "memory or sqlite")
	flag.StringVar(&c.DBPath, "db", "./netpolicy.data.json", "file store path")
	flag.StringVar(&c.DefaultAction, "default-action", "deny", "default action")
	flag.IntVar(&c.WorkerCount, "workers", 4, "worker count")
	flag.IntVar(&c.MaxRulesSync, "max-rules-sync", 2000, "sync rule limit")
	flag.Parse()
	return c
}
