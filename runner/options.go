package runner

import (
	"io"
	"os"
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool   // Verbose flag indicates whether to show verbose output or not
	NoColor            bool   // No-Color disables the colored output
	JSON               bool   // JSON specifies whether to use json for output format or text file
	Silent             bool   // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool   // ListSources specifies whether to list all available sources
	Stdin              bool   // Stdin specifies whether stdin input was given to the process
	Version            bool   // Version specifies if we should just show version and exit
	All                bool   // All specifies whether to use all (slow) sources.
	Threads            int    // Thread controls the number of threads to use for active enumerations
	Timeout            int    // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int    // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
	Threshold          int    // Threshold is Number of domain name thresholds
	Ip                 string // Ip is the domain to find subdomains for
	IpsFile            string // IpsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string // Output is the file to write found subdomains to.
	OutputDirectory    string // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            string // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     string // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	ConfigFile         string // ConfigFile contains the location of the config file

	YAMLConfig ConfigFile // YAMLConfig contains the unmarshalled yaml config file
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}
