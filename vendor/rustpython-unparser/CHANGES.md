Based on rustpython-unparser 0.2.4 by Jan Vollmer, MIT licensed.
Local fixes reproduce CPython ast.unparse for floats, bare return, singleton
tuples and positional-only argument separators. Auth51-specific docstring
removal, blank lines and f-string quote normalization live in src/auth51/source.rs.
