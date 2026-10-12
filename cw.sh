#!/usr/bin/env bash
cd /mnt/d/Axioms/Syrth
gh run view --job $(gh run view 38231770951 --json jobs --jq '.jobs[] | select(.name=="test (windows-latest, 3.12)").databaseId') --log-failed 2>&1 | tail -25