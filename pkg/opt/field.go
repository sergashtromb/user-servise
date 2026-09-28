package opt

import "encoding/json"

type Field[T any] struct {
	Value 	T
	Define 	bool
	Valid 	bool
}

func (f *Field[T]) UnmarshalJSON(data []byte) error {
	f.Define = true

	if string(data) == "null" {
		f.Valid = false
		return nil
	}

	f.Valid = true
	return json.Unmarshal(data, &f.Value)
}