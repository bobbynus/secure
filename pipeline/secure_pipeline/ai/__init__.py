"""Stage 4: AI texts and translations.

The model only writes prose around facts that come from the collector and the sources. Identifiers, CVSS,
exploitation and fix status are deterministic; versions and commands in the text must be found in the
source texts; translations must keep every identifier, version and code span. Anything that fails stays
in the queue (retry with backoff, then quarantine) instead of being published.
"""
