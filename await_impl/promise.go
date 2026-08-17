//go:build wasm

package await

import "syscall/js"

type Error string

func (e Error) Error() string { return string(e) }

const ErrRejected Error = "await: promise rejected"

func Promise(p js.Value) (js.Value, error) {
	resultCh := make(chan js.Value, 1)
	errCh := make(chan error, 1)

	then := js.FuncOf(func(_ js.Value, args []js.Value) any {
		var val js.Value
		if len(args) > 0 {
			val = args[0]
		}
		resultCh <- val
		return js.Undefined()
	})
	defer then.Release()

	catch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 {
			errVal := args[0]
			if !errVal.IsNull() && !errVal.IsUndefined() {
				if errVal.Type() == js.TypeString {
					msg = errVal.String()
				} else if !errVal.Get("message").IsUndefined() && !errVal.Get("message").IsNull() {
					msg = errVal.Get("message").String()
				} else if !errVal.Get("toString").IsUndefined() {
					msg = errVal.Call("toString").String()
				}
			}
		}
		errCh <- Error(msg)
		return js.Undefined()
	})
	defer catch.Release()

	p.Call("then", then).Call("catch", catch)
	select {
	case v := <-resultCh:
		return v, nil
	case err := <-errCh:
		return js.Value{}, err
	}
}
