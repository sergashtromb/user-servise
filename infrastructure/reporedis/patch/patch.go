package patch

type ActionField int

const (
	FPSetField ActionField = iota
	FPClearField
)

type FieldPatch struct {
	Name   string
	Action ActionField
	// only for action == FPSetField
	Value string
}

type Patch interface {
	Patches() []FieldPatch
}

func NewSetFPatch(fieldName string, value string) FieldPatch {
	return FieldPatch{
		Name:   fieldName,
		Action: FPSetField,
		Value:  value,
	}
}

func NewClearFPatch(fieldName string) FieldPatch {
	return FieldPatch{
		Name:   fieldName,
		Action: FPClearField,
	}
}
