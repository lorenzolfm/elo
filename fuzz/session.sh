# One fuzz session, in the image of `elo-fuzz-image`. Usage: session <seconds>
#
# At most two processes run, so a session holds at most two cores. One runs `machines` for the whole
# window, because it has the most states. The other runs each other target in turn. `compact_size`
# gets at most 60 s, because 84M runs in 30 s found a new input only at run 23. The other targets
# split the rest. No fork mode: a fork job deletes its panic text, and needs a writable /tmp.
#
# A crash ends its target for this session, so a session keeps at most one crash for each target.
# Then the session fails, so its Job fails and the alert on the last good session can fire.
#
# /targets and /corpus are in the image. /data holds all that the session writes:
#   /data/corpus/<target>/              the new inputs of each session
#   /data/crashes/<target>-<commit>-*   each crash, with the name that libFuzzer gives it
#   /data/logs/<target>.log             the libFuzzer log of the last session

fail() {
  echo "session: $1" >&2
  exit 2
}

# The shell and libFuzzer must read the window as one number. libFuzzer stops at the first character
# that is not a digit and keeps an `int`, and 0 is no limit. So 0x20 and 2^32 each remove the limit.
window_seconds="${1:-}"
case "$window_seconds" in
  '' | 0* | *[!0-9]*) fail "usage: session <seconds>, a decimal number above 0" ;;
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

# Floor divisions, so the second process ends inside the window. A share of 0 s would be no limit.
share_seconds=$((window_seconds / (${#others[@]} + 1)))
test "$share_seconds" -gt 0 || fail "need at least $((${#others[@]} + 1)) seconds"
compact_size_seconds=$((share_seconds < 60 ? share_seconds : 60))
other_seconds=$(((window_seconds - compact_size_seconds) / ${#others[@]}))

mkdir --parents /data/corpus /data/crashes /data/logs

# libFuzzer keeps a corpus in memory, so a large one looks like a leak. A mounted directory can also
# have no quota. So a session does not start with more than 1 GiB of these files. A person prunes
# them. Only these three directories count, because the session does not write the rest of /data.
data_size_kib="$(du --summarize --total --block-size=1K /data/corpus /data/crashes /data/logs |
  tail --lines=1 | cut --fields=1)"
test "$data_size_kib" -le $((1024 * 1024)) || fail "its files take $data_size_kib KiB, above 1 GiB"

# Each target has a small chain and, by the check above, a small corpus, so 1 GiB is a leak. Above
# this limit an allocation fails at once, so it is a crash with a file that holds its input, also
# when the target does not touch the memory. `-rss_limit_mb` does not do this. It reads the RSS once
# each second, so a fast allocation reaches the limit of a container first and no file holds the
# input, and its `oom-` file can hold a later input. Two processes at this limit fit in 3 GiB.
ulimit -v $((1024 * 1024)) || fail "cannot limit the address space"

# A script takes milliseconds, so 30 s is a hang, and that is a crash, with its own file. Each
# target reaches its limits from a short input, and with no `-max_len` the largest seed sets the
# length.
# A caller with `||` turns `errexit` off here, so each step that can fail says how `fuzz` ends.
fuzz() {
  local target="$1" limit_seconds="$2"
  local log="/data/logs/$target.log"
  mkdir --parents "/data/corpus/$target" || return 1
  echo "$target: start, $limit_seconds s, commit $ELO_COMMIT"
  if "/targets/$target" -max_total_time="$limit_seconds" -timeout=30 \
    -max_len=4096 -artifact_prefix="/data/crashes/$target-$ELO_COMMIT-" \
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
exit "$failed"
