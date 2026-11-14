#!/bin/bash
# Run once on D. Prints three lines to paste into multi/config.env (D keeps all three; T keeps only
# AGENT_SECRET_T; P keeps only AGENT_SECRET_P). Do not send them over chat or commit them.
r() { head -c 24 /dev/urandom | base64 | tr -d '/+=\n'; }
echo "AGENT_SECRET_T=$(r)"
echo "AGENT_SECRET_P=$(r)"
echo "DASH_PASS=$(r | head -c 14)"
echo "DASH_VIEW_PASS=$(r | head -c 14)      # optional: read-only account for the evaluator"
echo "DASH_SESSION_KEY=$(r)"
