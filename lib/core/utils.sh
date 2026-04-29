#!/bin/sh

is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

sanitize_positive_int() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*|0)
      printf '%s' "$fallback"
      ;;
    *)
      printf '%s' "$value"
      ;;
  esac
}
