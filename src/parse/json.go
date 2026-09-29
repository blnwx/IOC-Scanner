package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// JSON decodes a single JSON value and rejects any trailing garbage.
func JSON(reader io.Reader, value any) error {
	decoder := json.NewDecoder(reader)
	return JSONDecoder(decoder, value)
}

// JSONDecoder is the same check for callers that configure the decoder first.
func JSONDecoder(decoder *json.Decoder, value any) error {
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON: trailing data")
	}
	return nil
}
