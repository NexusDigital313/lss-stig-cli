# Build edition. Release builds ship "commercial" (license gate on).
# `tools/build_bundle.py --owner` writes "owner" into its own staged copy for
# the copyright holder's test media; this file always stays "commercial".
# Never publish an owner build.
EDITION = "commercial"
