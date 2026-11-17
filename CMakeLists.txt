your-project/
│
├── your-source-code/
│
└── nexpilor-reports/
    ├── analysis.json
    └── analysis.md

if path.suffix == ".py":
    self.analyze_python(path, source)

elif path.suffix == ".java":
    self.analyze_java(path, source)
