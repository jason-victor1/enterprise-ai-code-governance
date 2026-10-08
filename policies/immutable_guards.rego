package enterprise.immutable_guards

default allow = false

# Rule: Non-human identity (agent) cannot modify CI workflows or policies
deny[msg] {
    input.author_metadata.author_type == "agent"
    file := input.blast_radius.evaluated_files[_]
    is_immutable_path(file.path)
    msg := sprintf("[IMMUTABLE-GUARD-01] Agent identity attempted to modify protected infrastructure/policy path: '%v'", [file.path])
}

is_immutable_path(path) {
    startswith(path, ".github/")
}
is_immutable_path(path) {
    startswith(path, "policies/")
}
is_immutable_path(path) {
    endswith(path, "requirements.txt")
}
