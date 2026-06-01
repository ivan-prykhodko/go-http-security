package security

var (
	AccessGranted = AccessState{value: 1}
	AccessAbstain = AccessState{value: 0}
	AccessDenied  = AccessState{value: -1}
)

type AccessState struct {
	value int8
}

func (a AccessState) Equal(b AccessState) bool {
	return a.value == b.value
}
