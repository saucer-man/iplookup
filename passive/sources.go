package passive

import (
	"github.com/saucer-man/iplookup/subscraping"
	"github.com/saucer-man/iplookup/subscraping/sources/aizhan"
	"github.com/saucer-man/iplookup/subscraping/sources/bugscaner"
	"github.com/saucer-man/iplookup/subscraping/sources/c99"
	"github.com/saucer-man/iplookup/subscraping/sources/chinaz"
	"github.com/saucer-man/iplookup/subscraping/sources/dnsgrep"
	"github.com/saucer-man/iplookup/subscraping/sources/dnslytics"
	"github.com/saucer-man/iplookup/subscraping/sources/domaintools"
	"github.com/saucer-man/iplookup/subscraping/sources/hackertarget"
	"github.com/saucer-man/iplookup/subscraping/sources/ip138"
	"github.com/saucer-man/iplookup/subscraping/sources/omnisint"
	"github.com/saucer-man/iplookup/subscraping/sources/rapiddns"
	"github.com/saucer-man/iplookup/subscraping/sources/securitytrails"
	"github.com/saucer-man/iplookup/subscraping/sources/viewdns"
	"github.com/saucer-man/iplookup/subscraping/sources/webscan"
	"github.com/saucer-man/iplookup/subscraping/sources/yougetsignal"
)

// DefaultSources contains the list of fast sources used by default.
var DefaultSources = []string{
	"webscan",
	"rapiddns",
	"ip138",
	"yougetsignal",
	"aizhan",
	"chinaz",
	"viewdns",
	"bugscaner",
	"hackertarget",
	"dnslytics",
	"omnisint",
	"dnsgrep",
	"domaintools",
	"securitytrails",
}

// DefaultAllSources contains list of all sources
var DefaultAllSources = []string{
	"webscan",
	"rapiddns",
	"ip138",
	"yougetsignal",
	"aizhan",
	"c99",
	"chinaz",
	"viewdns",
	"bugscaner",
	"hackertarget",
	"dnslytics",
	"omnisint",
	"dnsgrep",
	"domaintools",
	"securitytrails",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source)}

	agent.addSources(sources)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "webscan":
			a.sources[source] = &webscan.Source{}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{}
		case "dnsgrep":
			a.sources[source] = &dnsgrep.Source{}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{}
		case "c99":
			a.sources[source] = &c99.Source{}
		case "ip138":
			a.sources[source] = &ip138.Source{}
		case "aizhan":
			a.sources[source] = &aizhan.Source{}
		case "omnisint":
			a.sources[source] = &omnisint.Source{}
		case "viewdns":
			a.sources[source] = &viewdns.Source{}
		case "bugscaner":
			a.sources[source] = &bugscaner.Source{}
		case "dnslytics":
			a.sources[source] = &dnslytics.Source{}
		case "domaintools":
			a.sources[source] = &domaintools.Source{}
		case "yougetsignal":
			a.sources[source] = &yougetsignal.Source{}
		case "chinaz":
			a.sources[source] = &chinaz.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
