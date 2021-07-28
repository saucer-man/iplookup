package runner

import (
	"errors"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if domain, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if options.Ip == "" && options.IpsFile == "" && !options.Stdin {
		return errors.New("no input list provided")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Validate threads and options
	if options.Threads == 0 {
		return errors.New("threads cannot be zero")
	}
	if options.Timeout == 0 {
		return errors.New("timeout cannot be zero")
	}
	return nil
}

// configureOutput configures the output on theS screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	// if options.Verbose {
	// 	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	// }
	// if options.NoColor {
	// 	gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	// }
	// if options.Silent {
	// 	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	// }
}
