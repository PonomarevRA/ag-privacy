"""Compile trusted regex specifications into .NET source-generated methods; never run this on page data."""
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "rules/regex.json"
data = source.read_bytes()
if len(data) > 65536:
    raise ValueError("regex-pack-limit")
pack = json.loads(data)
if set(pack) != {"schemaVersion", "rules"} or pack["schemaVersion"] != "ag-privacy-regex-v1" or not 1 <= len(pack["rules"]) <= 64:
    raise ValueError("invalid-regex-pack")
lines = ["using System.Text.RegularExpressions;", "namespace AgPrivacy;", "/// <summary>Generated at build time from trusted rules/regex.json. Do not edit by hand.</summary>", "public static partial class GeneratedRules", "{", '    public const string Version = "' + hashlib.sha256(data).hexdigest() + '";', "    public static readonly RegexRule[] All = ["]
entity_types = {"TEXT","KEY","NUMBER","BOOLEAN","KLOGIN","TRDACC","INN","KPP","OGRN","BIK","ACCOUNT","URL","PATH","PERSON","SECRET","GUID","IDENTIFIER","EMAIL","PHONE","ADDRESS"}
seen = set()
methods = []
for i, rule in enumerate(pack["rules"]):
    if set(rule) - {"id", "type", "pattern", "ignoreCase"} or not {"id", "type", "pattern"} <= set(rule):
        raise ValueError("invalid-regex-rule")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", rule["id"]) or rule["id"] in seen or rule["type"] not in entity_types or not isinstance(rule["pattern"], str) or len(rule["pattern"]) > 1024:
        raise ValueError("invalid-regex-rule")
    seen.add(rule["id"])
    options = "RegexOptions.CultureInvariant" + (" | RegexOptions.IgnoreCase" if rule.get("ignoreCase") else "")
    lines.append(f'        new({json.dumps(rule["id"])}, {json.dumps(rule["type"])}, Pattern{i}()),')
    methods += [f'    [GeneratedRegex({json.dumps(rule["pattern"])}, {options}, 100)]', f'    private static partial Regex Pattern{i}();']
lines += ["    ];", *methods, "}"]
output = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "src/AgPrivacy.Core/GeneratedRules.cs"
output.write_text("\n".join(lines) + "\n")
print("Generated", len(seen), "source-compiled patterns", hashlib.sha256(data).hexdigest())
