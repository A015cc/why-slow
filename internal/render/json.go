package render

import (
	"encoding/json"
	"io"

	"github.com/A015cc/why-slow/internal/model"
)

// JSON writes the report as a stable, struct-driven JSON document.
//
// The output shape is exactly model.Report: nothing here adds fields, renames
// keys, or builds the document out of maps (whose key order would be
// non-deterministic). Severity and Confidence marshal as their string names
// through the MarshalJSON methods on those types, so consumers see
// "warning"/"medium" rather than opaque integers.
func JSON(w io.Writer, r *model.Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}
