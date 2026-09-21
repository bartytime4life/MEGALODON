#!/usr/bin/env bash
set -euo pipefail

mode="${1:---validate}"
case "${mode}" in
  --validate|--publish) ;;
  *)
    echo "usage: $0 [--validate|--publish]" >&2
    exit 2
    ;;
esac

runtime_tmp="${RUNNER_TEMP:-/tmp}"
content_dir="$(mktemp -d "${runtime_tmp}/megalodon-wiki-content.XXXXXX")"
wiki_dir=''

cleanup() {
  rm -rf "${content_dir}"
  if [[ -n "${wiki_dir}" ]]; then
    rm -rf "${wiki_dir}"
  fi
}
trap cleanup EXIT

shopt -s nullglob
source_pages=(docs/wiki/*.md)
if (( ${#source_pages[@]} == 0 )); then
  echo 'No Markdown pages found under docs/wiki.' >&2
  exit 1
fi

for source_page in "${source_pages[@]}"; do
  filename="$(basename "${source_page}")"
  destination="${filename}"
  if [[ "${filename}" == 'README.md' ]]; then
    destination='Home.md'
  fi
  cp "${source_page}" "${content_dir}/${destination}"
done

if [[ ! -s "${content_dir}/Home.md" ]]; then
  echo 'docs/wiki/README.md must exist and be non-empty.' >&2
  exit 1
fi

# Wiki-local links omit .md; repository links point back to main explicitly.
sed -i -E 's|\(([^:/)#]+)\.md(#[^)]+)?\)|(\1\2)|g' "${content_dir}"/*.md

repo_blob_root="https://github.com/${GITHUB_REPOSITORY:-bartytime4life/MEGALODON}/blob/main"
sed -i \
  -e "s#(../../SPECIFICATION.md#(${repo_blob_root}/SPECIFICATION.md#g" \
  -e "s#(../../SECURITY_REVIEW.md#(${repo_blob_root}/SECURITY_REVIEW.md#g" \
  -e "s#(../../CONTRIBUTING.md#(${repo_blob_root}/CONTRIBUTING.md#g" \
  -e "s#(../../README.md#(${repo_blob_root}/README.md#g" \
  -e "s#(../platform-baseline.md#(${repo_blob_root}/docs/platform-baseline.md#g" \
  -e "s#(../local-pc-setup.md#(${repo_blob_root}/docs/local-pc-setup.md#g" \
  -e "s#(../gui-quick-start.md#(${repo_blob_root}/docs/gui-quick-start.md#g" \
  -e "s#(../software-downloads.md#(${repo_blob_root}/docs/software-downloads.md#g" \
  -e "s#(../document-alignment-2026-09-20.md#(${repo_blob_root}/docs/document-alignment-2026-09-20.md#g" \
  -e "s#(../dashboard-operations.md#(${repo_blob_root}/docs/dashboard-operations.md#g" \
  -e "s#(../integration-hub.md#(${repo_blob_root}/docs/integration-hub.md#g" \
  -e "s#(../local-model-advisory-contract.md#(${repo_blob_root}/docs/local-model-advisory-contract.md#g" \
  "${content_dir}"/*.md

if grep -REn '\]\(\.\./' "${content_dir}"; then
  echo 'Unresolved repository-relative Wiki link found.' >&2
  exit 1
fi

declare -A listed=()
preferred_pages=(
  quick-start
  security-boundaries
  operator-guide
  integrations-and-qwen
  development-and-validation
  roadmap-and-limits
)

{
  echo '* [Home](Home)'
  for slug in "${preferred_pages[@]}"; do
    page="${content_dir}/${slug}.md"
    if [[ -f "${page}" ]]; then
      title="$(sed -n 's/^# //p' "${page}" | head -n 1)"
      title="${title:-${slug//-/ }}"
      printf '* [%s](%s)\n' "${title}" "${slug}"
      listed["${slug}"]=1
    fi
  done

  for page in "${content_dir}"/*.md; do
    slug="$(basename "${page}" .md)"
    [[ "${slug}" == 'Home' ]] && continue
    [[ -n "${listed[${slug}]+x}" ]] && continue
    title="$(sed -n 's/^# //p' "${page}" | head -n 1)"
    title="${title:-${slug//-/ }}"
    printf '* [%s](%s)\n' "${title}" "${slug}"
  done
} > "${content_dir}/_Sidebar.md"

cat > "${content_dir}/_Footer.md" <<'EOF'
This Wiki is generated from the version-controlled `docs/wiki` directory in the MEGALODON repository.
EOF

echo "Prepared $(find "${content_dir}" -maxdepth 1 -type f -name '*.md' | wc -l) Wiki files."

if [[ "${mode}" == '--validate' ]]; then
  wiki_dir="$(mktemp -d "${runtime_tmp}/megalodon-wiki-validation.XXXXXX")"
  python3 tools/sync_wiki_pages.py "${content_dir}" "${wiki_dir}"
  exit 0
fi

: "${GH_TOKEN:?GH_TOKEN is required for publication}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required for publication}"
: "${GITHUB_SHA:?GITHUB_SHA is required for publication}"

wiki_dir="$(mktemp -d "${runtime_tmp}/megalodon-wiki-repository.XXXXXX")"
wiki_url="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.wiki.git"
git clone "${wiki_url}" "${wiki_dir}"
wiki_branch="$(git -C "${wiki_dir}" branch --show-current)"
wiki_branch="${wiki_branch:-master}"

python3 tools/sync_wiki_pages.py "${content_dir}" "${wiki_dir}"

git -C "${wiki_dir}" config user.name 'github-actions[bot]'
git -C "${wiki_dir}" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git -C "${wiki_dir}" add --all

if git -C "${wiki_dir}" diff --cached --quiet; then
  echo 'Wiki is already current.'
else
  git -C "${wiki_dir}" commit -m "docs: publish MEGALODON wiki from ${GITHUB_SHA}"
  git -C "${wiki_dir}" push origin "HEAD:${wiki_branch}"
fi

page_url="https://github.com/${GITHUB_REPOSITORY}/wiki/Home"
response_file="${runtime_tmp}/wiki-home.html"

for attempt in {1..12}; do
  status="$(curl --location --silent --show-error --output "${response_file}" --write-out '%{http_code}' "${page_url}" || true)"
  if [[ "${status}" == '200' ]] && grep -Fq 'MEGALODON Documentation Wiki' "${response_file}"; then
    echo "Verified ${page_url}"
    exit 0
  fi

  echo "Wiki verification attempt ${attempt} returned HTTP ${status}; retrying."
  sleep 5
done

echo "Failed to verify ${page_url}." >&2
exit 1
