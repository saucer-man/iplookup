package runner

import (
	"bufio"
	"context"
	"io"
	"os"

	"github.com/saucer-man/iplookup/passive"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	passiveAgent *passive.Agent
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine() //初始化api接口
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumeration(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	// Check if only a single domain is sent as input. Process the domain now.
	if r.options.Ip != "" {

		return r.EnumerateSingleDomain(ctx, r.options.Ip, outputs)
	}

	// If we have multiple domains as input,  从文件中添加
	if r.options.IpsFile != "" {
		f, err := os.Open(r.options.IpsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomains(ctx, f, outputs)
		f.Close()
		return err
	}

	// If we have STDIN input, treat it as multiple domains  从输入流添加进扫描
	if r.options.Stdin {
		return r.EnumerateMultipleDomains(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomains enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error   枚举多个子域名
func (r *Runner) EnumerateMultipleDomains(ctx context.Context, reader io.Reader, outputs []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		ip := scanner.Text()
		if ip == "" {
			continue
		}

		var err error

		err = r.EnumerateSingleDomain(ctx, ip, outputs)
		if err != nil {
			return err
		}
	}
	return nil
}
