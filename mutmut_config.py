def pre_mutation(context):
    # Skip test files and third-party files
    if "tests" in context.filename or "__init__" in context.filename:
        context.skip = True
