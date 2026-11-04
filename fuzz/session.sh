# One fuzz session, in the image of `elo-fuzz-image`. Usage: session <seconds>
#
# Two processes run at all times, so a session holds two cores. One runs `machines` for the whole
# window, because it has the most states. The other runs each other target in turn, and the window
# is split between them. No fork mode: a fork job deletes its panic text, and needs a writable /tmp.
#
# A crash ends its target for this session, so a session keeps at most one crash for each target.
# Then the session fails, so its Job fails and the alert on the last good session can fire.
#
# /targets and /corpus are in the image. /data holds all that the session writes:
#   /data/corpus/<target>/              the new inputs of each session
#   /data/crashes/<target>-<commit>-*   each crash, with the name that libFuzzer gives it
#   /data/logs/<target>.log             the libFuzzer log of the last session

seconds="$1"

others=()
for path in /targets/*; do
  target="${path##*/}"
  if test "$target" != machines; then
    others+=("$target")
  fi
done
other_seconds=$((seconds / ${#others[@]}))
if test ! -x /targets/machines || test "$other_seconds" -le 0; then
  echo "session: need /targets/machines, and at least ${#others[@]} seconds" >&2
  exit 2
fi

mkdir -p /data/crashes /data/logs

# A script takes milliseconds, so 30 s is a hang. Each target has a small chain and a small corpus,
# so 1 GiB is a leak. Each one is a crash, with its own file.
fuzz() {
  local target="$1" limit="$2" log="/data/logs/$1.log"
  mkdir -p "/data/corpus/$target"
  echo "$target: start, $limit s, commit $ELO_COMMIT"
  if "/targets/$target" -max_total_time="$limit" -timeout=30 -rss_limit_mb=1024 \
    -artifact_prefix="/data/crashes/$target-$ELO_COMMIT-" \
    "/data/corpus/$target" "/corpus/$target" >"$log" 2>&1; then
    echo "$target: $(grep --extended-regexp '^#[0-9]+\s+DONE' "$log" | tail --lines=1)"
  else
    echo "$target: FAILED with status $?, log in $log"
    grep --after-context=1 --extended-regexp 'panicked at|^==[0-9]+== ERROR' "$log" | head --lines=8
    return 1
  fi
}

fuzz_others() {
  local failed=0
  for target in "${others[@]}"; do
    fuzz "$target" "$other_seconds" || failed=1
  done
  return "$failed"
}

fuzz machines "$seconds" &
machines_pid=$!
fuzz_others &
others_pid=$!

failed=0
wait "$machines_pid" || failed=1
wait "$others_pid" || failed=1
exit "$failed"
