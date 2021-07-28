package iplookup

import (
	"context"
	"os"

	"github.com/saucer-man/iplookup/passive"
	"github.com/saucer-man/iplookup/runner"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
)

func LookUp(ip string) error {
	config := runner.ConfigFile{
		// Use the default list of passive sources
		Sources: passive.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive.DefaultAllSources,
		// Use the default list of recursive sources
	}
	options := &runner.Options{
		Ip:                 ip,
		YAMLConfig:         config,
		Threads:            30,
		NoColor:            true,
		Silent:             true,
		Timeout:            10,
		MaxEnumerationTime: 10,
		Threshold:          30,
		Output:             os.Stdout,
	}
	newRunner, err := runner.NewRunner(options)
	if err != nil {
		return err
	}

	err = newRunner.RunEnumeration(context.Background())
	return err
}
