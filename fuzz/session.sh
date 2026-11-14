fail() {
  echo "session: $1" >&2
  exit 2
}

usage="usage: session <seconds>, a decimal number above 0"
test "$#" -eq 1 || fail "$usage"
window_seconds="$1"
case "$window_seconds" in
  '' | 0* | *[!0-9]*) fail "$usage" ;;
esac
test "$window_seconds" -le 86400 || fail "the window is more than one day"

test -x /targets/machines || fail "need /targets/machines"
test -x /targets/compact_size || fail "need /targets/compact_size"

others=()
for path in /targets/*; do
  other="${path##*/}"
  case "$other" in
    compact_size | machines) ;;
    *) others+=("$other") ;;
  esac
done
test "${#others[@]}" -gt 0 || fail "need a target other than machines and compact_size"

share_seconds=$((window_seconds / (${#others[@]} + 1)))
test "$share_seconds" -gt 0 || fail "need at least $((${#others[@]} + 1)) seconds"
compact_size_seconds=$((share_seconds < 60 ? share_seconds : 60))
other_seconds=$(((window_seconds - compact_size_seconds) / ${#others[@]}))

mkdir --parents /data/corpus /data/crashes /data/logs || fail "cannot write to /data"

data_size_kib="$(du --summarize --total --block-size=1K /data/corpus /data/crashes /data/logs |
  tail --lines=1 | cut --fields=1)" || fail "cannot read the size of /data"
test "$data_size_kib" -le $((1024 * 1024)) || fail "its files take $data_size_kib KiB, above 1 GiB"

ulimit -v $((1024 * 1024)) || fail "cannot limit the address space"

fuzz() {
  local target="$1" limit_seconds="$2"
  local log="/data/logs/$target.log"
  mkdir --parents "/data/corpus/$target" || return 1
  echo "$target: start, $limit_seconds s, commit $ELO_COMMIT"
  if "/targets/$target" -max_total_time="$limit_seconds" -timeout=30 \
    -max_len=4096 -report_slow_units=3600 -artifact_prefix="/data/crashes/$target-$ELO_COMMIT-" \
    "/data/corpus/$target" "/corpus/$target" >"$log" 2>&1; then
    echo "$target: $(grep --extended-regexp '^#[0-9]+\s+DONE' "$log" | tail --lines=1)"
  else
    echo "$target: FAILED with status $?, log in $log"
    grep --after-context=1 --extended-regexp 'panicked at|^==[0-9]+== ERROR' "$log" |
      head --lines=8 || true
    return 1
  fi
}

fuzz_others() {
  local failed=0 target
  fuzz compact_size "$compact_size_seconds" || failed=1
  for target in "${others[@]}"; do
    fuzz "$target" "$other_seconds" || failed=1
  done
  return "$failed"
}

fuzz machines "$window_seconds" &
machines_pid=$!
fuzz_others &
others_pid=$!

failed=0
wait "$machines_pid" || failed=1
wait "$others_pid" || failed=1

crash_files="$(ls --almost-all /data/crashes)" || failed=1
if test -n "$crash_files"; then
  echo "session: a person must read and remove these files in /data/crashes:"
  echo "$crash_files"
  failed=1
fi
exit "$failed"
