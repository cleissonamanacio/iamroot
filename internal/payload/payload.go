//go:build !iamrootfull

package payload

func Has(name string) bool              { return false }
func Available() bool                   { return false }
func Ready(name string) bool            { return false }
func Run(name, persistUser string) bool { return false }
