package runner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/saucer-man/iplookup/subscraping"

	jsoniter "github.com/json-iterator/go"
)

// OutPutter outputs content to writers.
type OutPutter struct {
	JSON bool
}

type jsonResult struct {
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Source string `json:"source"`
}

type jsonSourceResult struct {
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
}

// NewOutputter creates a new Outputter
func NewOutputter(json bool) *OutPutter {
	return &OutPutter{JSON: json}
}

func (o *OutPutter) createFile(filename string, appendtoFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	dir := filepath.Dir(filename)

	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
	}

	var file *os.File
	var err error
	if appendtoFile {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// WriteHost writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteHost(results map[string]subscraping.HostEntry, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeJSONHost(results, writer)
	} else {
		err = writePlainHost(results, writer)
	}
	return err
}

func writePlainHost(results map[string]subscraping.HostEntry, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func writeJSONHost(results map[string]subscraping.HostEntry, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	for _, result := range results {
		err := encoder.Encode(result)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteSourceHost writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteSourceHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeSourceJSONHost(sourceMap, writer)
	} else {
		err = writeSourcePlainHost(sourceMap, writer)
	}
	return err
}

func writeSourceJSONHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	var data jsonSourceResult

	for host, sources := range sourceMap {
		data.Host = host
		keys := make([]string, 0, len(sources))
		for source := range sources {
			keys = append(keys, source)
		}
		data.Sources = keys

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeSourcePlainHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host, sources := range sourceMap {
		sb.WriteString(host)
		sb.WriteString(",[")
		sourcesString := ""
		for source := range sources {
			sourcesString += source + ","
		}
		sb.WriteString(strings.Trim(sourcesString, ", "))
		sb.WriteString("]\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}
