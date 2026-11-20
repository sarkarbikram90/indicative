#!/usr/bin/env bash
set -euo pipefail
# Controlled Trivy offline DB & checks update script.
# Run in a trusted CI/maintenance environment — NEVER inside untrusted scan execution.
CACHE_DIR="${TRIVY_CACHE_DIR:-./.trivy-cache}"
mkdir -p "${CACHE_DIR}"
echo "[indicative] Updating offline Trivy vulnerability DB in ${CACHE_DIR}..."
trivy fs --download-db-only --cache-dir "${CACHE_DIR}"
echo "[indicative] Updating offline Trivy misconfiguration checks in ${CACHE_DIR}..."
trivy fs --download-checks-only --cache-dir "${CACHE_DIR}" || true
echo "[indicative] Trivy offline cache updated successfully."
