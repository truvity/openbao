package builder

import (
	"bytes"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// Load reads a [Spec] authored as YAML. It refuses a field it does not know,
// and more than one document: a misspelled key is a grant its author
// expected to be there.
func Load(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("builder: read spec: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var spec Spec
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("builder: decode spec: %w", err)
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("builder: a spec is one YAML document")
	}

	return &spec, nil
}
