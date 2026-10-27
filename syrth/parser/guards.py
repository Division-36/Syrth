"""Recognise guard constructs that constrain a tainted value.

A guard is *not* a sanitiser: it never clears ``origins`` and never satisfies
patch verification. It is graded evidence, used to rank a finding.

Recognised shapes, in ``if <test>: <terminal body>`` form:

* ``value in ("a", "b")`` / ``value not in ALLOWED`` -- allowlist or denylist
* ``value == "x"`` / ``value != "x"`` -- equality
* ``value.startswith("x")`` / ``endswith`` -- prefix/suffix

The container must be a literal set of constants, or a name bound to one. A
membership test against an unbounded collection (``value in request.COOKIES``)
constrains nothing and is not recognised.
"""

from __future__ import annotations

from typing import Any

LITERAL_CONTAINER_TYPES = frozenset({"tuple", "list", "set"})
COMPARISON_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "in", "not in"})
STRING_METHODS = frozenset({"startswith", "endswith"})


_STRING_PREFIXES = ("rb", "br", "fr", "rf", "r", "b", "f", "u")
_QUOTES = ('"""', "'''", '"', "'")


def _string_value(node: Any, raw: bytes) -> str:
    """The literal contents of a string node, with prefix and quotes removed.

    Order matters: strip the prefix first, then the matching pair of quotes.
    Stripping the prefix and only the closing quote leaves a leading quote
    attached to the value, which silently broke every anchored-regex check.
    """
    text = raw[node.start_byte : node.end_byte].decode("utf-8", "replace")
    for prefix in _STRING_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    for quote in _QUOTES:
        if len(text) >= 2 * len(quote) and text.startswith(quote) and text.endswith(quote):
            return text[len(quote) : -len(quote)]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def literal_constants(node: Any, raw: bytes) -> tuple[str, ...] | None:
    """Return the constants of a literal container, else ``None``.

    ``None`` means "not a closed literal set", which is what keeps
    ``value in some_runtime_set`` from being mistaken for an allowlist.
    """
    if node is None or node.type not in LITERAL_CONTAINER_TYPES:
        return None
    values: list[str] = []
    for child in node.named_children:
        if child.type == "string":
            values.append(_string_value(child, raw))
        elif child.type in ("integer", "float"):
            values.append(child.text.decode("utf-8", "replace"))
        else:
            return None
    return tuple(values) if values else None


def _identifier(node: Any) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return node.text.decode("utf-8", "replace")
    return None


#: Separators a filename pattern must exclude. NUL is not listed because
#: ``open()`` raises ``ValueError`` on an embedded null byte, so it cannot be
#: used to traverse; the separator set is what actually decides safety.
_PATH_SEPARATORS = ("/", "\\")

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "f": "\f", "v": "\v", "0": "\0", "a": "\a", "b": "\b"}


def _decode_class(body: str) -> str | None:
    """Decode the members of a character class, honouring escapes.

    ``[\\w-]`` must not be read as containing a backslash separator: inside a
    class the backslash escapes the ``w``. Returns the decoded characters, or
    ``None`` when the class uses a form we refuse to interpret.
    """
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(body):
            return None
        nxt = body[index + 1]
        if nxt == "x":
            hex_digits = body[index + 2 : index + 4]
            if len(hex_digits) < 2:
                return None
            try:
                out.append(chr(int(hex_digits, 16)))
            except ValueError:
                return None
            index += 4
            continue
        out.append(_ESCAPES.get(nxt, nxt))
        index += 2
    return "".join(out)


def _regex_is_path_safe(pattern: str) -> bool:
    """True when an anchored regex excludes every path separator.

    ``^[a-z0-9_]+\\.log$`` cannot contain ``/``, so a value that passes it cannot
    escape a directory. Everything that *can* match a separator is rejected:

    * ``.`` -- it matches any character except newline, so it matches ``/``;
    * ``\\D``, ``\\W`` -- negated shorthands, which admit ``/``;
    * an unescaped ``/``;
    * a negated class that does not name both ``/`` and ``\\``, because
      ``[^/]`` still admits ``\\`` on Windows.

    Rejecting is deliberately one-sided. Declaring a hostile pattern safe would
    hide a traversal; refusing to bless a defensive one only costs a warning.
    """
    if not pattern:
        return False
    body = pattern.strip()
    if not body.startswith("^"):
        return False
    body = body[1:]
    if not (body.endswith("$") or body.endswith(r"\Z") or body.endswith(r"\z")):
        return False

    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            if index + 1 >= len(body):
                return False
            following = body[index + 1]
            if following in ("/", "\\", "\x00"):
                return False
            # Negated shorthands admit a separator even though they look narrow.
            # This is checked here rather than by a whole-pattern search so that
            # ``[\w-]``, where the shorthand is already confined by the class,
            # is not rejected along with it.
            if following in ("D", "W"):
                return False
            index += 2
            continue
        if char in ("/", "\x00"):
            return False
        if char == ".":
            # ``.`` matches any character except a newline, including ``/``.
            # ``\.`` was already consumed by the escape branch above.
            return False
        if char == "[":
            close = body.find("]", index)
            if close == -1:
                return False
            raw_members = body[index + 1 : close]
            negated = raw_members.startswith("^")
            if negated:
                raw_members = raw_members[1:]
            decoded = _decode_class(raw_members)
            if decoded is None:
                return False
            if negated:
                # The class admits anything it does not name, so it must name
                # both separators to be safe: ``[^/]`` still lets ``\\`` through
                # on Windows.
                if any(sep not in decoded for sep in _PATH_SEPARATORS):
                    return False
            elif any(sep in decoded for sep in _PATH_SEPARATORS):
                return False
            index = close + 1
            continue
        index += 1
    return True


def classify_regex_guard(test: Any, raw: bytes) -> str | None:
    """Return the guarded variable for a terminating regex validation.

    Handles ``re.match(r"...", x)`` and ``re.fullmatch(r"...", x)``. The
    *negative* form ``if not re.match(...): return`` is the common one and is
    recognised by the caller through :func:`is_negated`.
    """
    if test is None or test.type != "call":
        return None
    children = list(test.named_children)
    if len(children) < 2:
        return None
    func = children[0]
    name = ""
    if func.type == "identifier":
        name = func.text.decode("utf-8", "replace")
    elif func.type == "attribute":
        # ``re.match`` is an ``attribute`` node with an ``attribute`` field for
        # the method name. Reading the field is portable; scanning children for
        # an *unnamed* token is not, because some grammar versions mark the
        # method name as a named identifier.
        method_node = func.child_by_field_name("attribute")
        if method_node is not None:
            name = method_node.text.decode("utf-8", "replace")
    if name not in ("match", "fullmatch", "search"):
        return None

    # Arguments arrive wrapped in an ``argument_list`` node, not as bare call
    # children, so the pattern is the first child *of that list*.
    arguments = children[1]
    if arguments.type != "argument_list":
        return None
    arg_nodes = list(arguments.named_children)
    if len(arg_nodes) < 2:
        return None

    pattern_node = arg_nodes[0]
    if pattern_node.type != "string":
        return None
    if not _regex_is_path_safe(_string_value(pattern_node, raw)):
        return None
    return _identifier(arg_nodes[1])


def is_negated(test: Any) -> bool:
    """True when the test is wrapped in a ``not``."""
    if test is None:
        return False
    if test.type == "not_operator":
        return True
    return False


def unwrap_not(test: Any) -> Any:
    """Strip a ``not`` wrapper."""
    if test is not None and test.type == "not_operator":
        for child in test.named_children:
            return child
    return test


def classify_test(test: Any, raw: bytes) -> tuple[str, str] | None:
    """Classify an ``if`` test.

    Returns:
        ``(guard_kind, variable_name)``, or ``None`` when the test is not a
        recognised guard.
    """
    if test is None:
        return None

    if test.type == "comparison_operator":
        children = list(test.named_children)
        if len(children) != 2:
            return None
        left, right = children
        operator = ""
        for child in test.children:
            if not child.is_named:
                text = child.text.decode("utf-8", "replace").strip()
                if text in COMPARISON_OPS:
                    operator = text
                    break
        if not operator:
            return None
        name = _identifier(left)
        if name is None:
            return None
        if operator in ("in", "not in"):
            if literal_constants(right, raw) is None and right.type != "identifier":
                return None
            # The classification follows what the *fall-through* path knows, not
            # the operator's surface form:
            #   ``if x not in ALLOWED: return``  -> x is in ALLOWED  (allowlist)
            #   ``if x in BLOCKED: return``      -> x avoids BLOCKED  (denylist)
            # Getting this backwards downgrades the strong pattern to the weak
            # one, which is exactly the mistake that left guarded code
            # reported as a finding.
            return ("denylist" if operator == "in" else "allowlist"), name
        return "equality", name

    if test.type == "call":
        children = list(test.named_children)
        if len(children) < 2:
            return None
        func = children[0]
        if func.type != "attribute":
            return None
        # ``x.startswith("a")`` lays out as [<obj>, ".", "startswith", "(", ...];
        # the method name is the unnamed field rather than a nested node.
        method = ""
        for child in func.children:
            if not child.is_named:
                text = child.text.decode("utf-8", "replace").strip()
                if text and text != ".":
                    method = text
                    break
        if method not in STRING_METHODS:
            return None
        name = _identifier(children[1])
        if name is None:
            return None
        return "equality", name

    return None


def body_terminates(block: Any, raw: bytes) -> bool:
    """True when ``block`` leaves the enclosing function or loop.

    ``if cmd not in ALLOWED: return`` terminates, so the code after it only
    sees allowlisted values. ``if cmd in ALLOWED: use(cmd)`` does not, so it is
    not a guard on the fall-through path.
    """
    if block is None:
        return False
    if block.type != "block":
        text = raw[block.start_byte : block.end_byte].decode("utf-8", "replace")
        return text.lstrip().startswith(("return", "raise", "continue", "break"))
    for child in block.named_children:
        if child.type in ("return_statement", "raise_statement"):
            return True
        if child.type == "if_statement":
            # Only terminates when both branches do; be conservative.
            return False
    return False


def guard_condition(block: Any) -> Any | None:
    """Return the ``if`` node itself, for ``if not cond: return`` shapes."""
    return block if block is not None and block.type == "if_statement" else None
