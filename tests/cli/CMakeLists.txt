add_test(NAME cli-help COMMAND youtube-unthrottle --help)
add_test(NAME cli-try-sandbox COMMAND youtube-unthrottle --try-sandbox)

macro(register_pass name expr)
	set_property(TEST ${name} PROPERTY PASS_REGULAR_EXPRESSION ${expr})
endmacro()

add_test(NAME cli-missing-url COMMAND youtube-unthrottle)
register_pass(cli-missing-url "Missing URL")

add_test(NAME cli-missing-proof-of-origin COMMAND
	youtube-unthrottle foobar.test
)
register_pass(cli-missing-proof-of-origin "Missing --proof-of-origin")
add_test(NAME cli-invalid-proof-of-origin COMMAND
	youtube-unthrottle foobar.test --proof-of-origin ""
)
register_pass(cli-invalid-proof-of-origin "Missing --proof-of-origin")
add_test(NAME cli-dangling-proof-of-origin COMMAND
	youtube-unthrottle foobar.test --proof-of-origin
)
register_pass(cli-dangling-proof-of-origin "requires an argument")

add_test(NAME cli-missing-visitor-data COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p
)
register_pass(cli-missing-visitor-data "Missing --visitor-data")
add_test(NAME cli-invalid-visitor-data COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data ""
)
register_pass(cli-invalid-visitor-data "Missing --visitor-data")
add_test(NAME cli-dangling-visitor-data COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data
)
register_pass(cli-dangling-visitor-data "requires an argument")

add_test(NAME cli-invalid-quality COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data v
	--quality +
)
register_pass(cli-invalid-quality "Invalid --quality")
add_test(NAME cli-dangling-quality COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data v
	--quality
)
register_pass(cli-dangling-quality "requires an argument")

add_test(NAME cli-invalid-arg COMMAND youtube-unthrottle --foobar)
register_pass(cli-invalid-arg "un(recognized|known)")
add_test(NAME cli-invalid-arg-overrides-valid-args COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data v
	--foobar
)
register_pass(cli-invalid-arg-overrides-valid-args "un(recognized|known)")
add_test(NAME cli-invalid-arg-overrides-help COMMAND
	youtube-unthrottle --help --foobar
)
register_pass(cli-invalid-arg-overrides-help "un(recognized|known)")
add_test(NAME cli-invalid-arg-overrides-try-sandbox COMMAND
	youtube-unthrottle --try-sandbox --foobar
)
register_pass(cli-invalid-arg-overrides-try-sandbox "un(recognized|known)")

add_test(NAME cli-valid-args-invalid-hostname COMMAND
	youtube-unthrottle foobar.test --proof-of-origin p --visitor-data v
)
register_pass(cli-valid-args-invalid-hostname "Could ?n.t resolve host ?name")
