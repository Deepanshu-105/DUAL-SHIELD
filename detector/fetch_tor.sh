#!/bin/bash
curl -sSf https://check.torproject.org/torbulkexitlist -o tor_exit_nodes.txt && wc -l tor_exit_nodes.txt
