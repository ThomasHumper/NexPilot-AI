if path.suffix == ".py":
    self.analyze_python(path, source)
  
def analyze_java(self, path, source):
    """Analyze Java source files."""

    self.stats["java_files"] += 1

    # Count classes, interfaces, enums and records
    classes = re.findall(
        r"\b(class|interface|enum|record)\s+\w+",
        source
    )

    self.stats["java_classes"] += len(classes)

    # Approximate method count
    methods = re.findall(
        r"\b(?:public|private|protected|static|final|synchronized|abstract|\s)+"
        r"[\w<>\[\], ?]+\s+\w+\s*\([^;{}]*\)\s*"
        r"(?:throws\s+[\w, ]+\s*)?\{",
        source
    )

    self.stats["java_methods"] += len(methods)

    # Check basic brace balance
    if source.count("{") != source.count("}"):
        self.findings.append(Finding(
            "HIGH",
            "Java structure",
            "Unbalanced opening and closing braces",
            path
        ))

    java_security_rules = [
        (
            "HIGH",
            "Command execution",
            re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\(")
        ),
        (
            "HIGH",
            "Process execution",
            re.compile(r"\bnew\s+ProcessBuilder\s*\(")
        ),
        (
            "HIGH",
            "Potential SQL injection",
            re.compile(
                r"""(?i)(?:executeQuery|executeUpdate|execute)\s*\([^)]*\+"""
            )
        ),
        (
            "HIGH",
            "Unsafe deserialization",
            re.compile(r"\bObjectInputStream\b")
        ),
        (
            "MEDIUM",
            "Weak random generator",
            re.compile(r"\bnew\s+Random\s*\(")
        ),
        (
            "MEDIUM",
            "Insecure HTTP configuration",
            re.compile(r"\bTrustAllStrategy\b|NoopHostnameVerifier")
        )
    ]

    for number, line in enumerate(source.splitlines(), 1):
        for severity, category, pattern in java_security_rules:
            if pattern.search(line):
                self.findings.append(Finding(
                    severity,
                    "Java security: " + category,
                    "Potential security issue requiring manual review",
                    path,
                    number
                ))

        if "TODO" in line or "FIXME" in line:
            self.findings.append(Finding(
                "LOW",
                "Java technical debt",
                line.strip()[:160],
                path,
                number
            ))
