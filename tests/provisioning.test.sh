#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

run_case() {
  local present="$1" temp_dir env_file log_file
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "${temp_dir}"' RETURN
  env_file="${temp_dir}/.env"
  log_file="${temp_dir}/docker.log"
  PROVISION_ENV_FILE="${env_file}" MOCK_LOG="${log_file}" MOCK_MODEL_PRESENT="${present}" bash -c '
    source ./provision
    create_env >/dev/null
    dotenv_set COMPOSE_PROFILES local-db,ai "$ENV_FILE"
    docker() {
      printf "%s\n" "$*" >> "$MOCK_LOG"
      case "$1" in
        info) return 0 ;;
        compose)
          case " $* " in
            *" compose --env-file $ENV_FILE exec -T ollama ollama list "*)
              printf "NAME ID SIZE MODIFIED\n"
              [[ "$MOCK_MODEL_PRESENT" == 1 ]] && printf "%s id size now\n" "$OLLAMA_MODEL"
              ;;
          esac
          return 0 ;;
      esac
    }
    main >/dev/null
  '
  grep -F "compose --env-file ${env_file} up -d --build --wait --wait-timeout 180" "${log_file}"
  grep -F "compose --env-file ${env_file} exec -T backend npm run seed:local" "${log_file}"
  if [[ "${present}" == 1 ]]; then
    ! grep -q 'ollama ollama pull' "${log_file}"
  else
    grep -q 'ollama ollama pull' "${log_file}"
  fi
}

run_case 0
run_case 1

temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT
env_file="${temp_dir}/.env"
PROVISION_ENV_FILE="${env_file}" bash -c 'source ./provision; create_env; load_runtime_values'
test "$(stat -c %a "${env_file}" 2>/dev/null || stat -f %Lp "${env_file}")" = 600
first_hash="$(shasum -a 256 "${env_file}" | awk '{print $1}')"
PROVISION_ENV_FILE="${env_file}" bash -c 'source ./provision; create_env; load_runtime_values'
test "${first_hash}" = "$(shasum -a 256 "${env_file}" | awk '{print $1}')"

cp .env.example "${temp_dir}/custom.env"
sed -i.bak 's/^APP_PORT=8080$/APP_PORT=8181/; s|^GOOGLE_REDIRECT_URI=.*$|GOOGLE_REDIRECT_URI=http://localhost:8080/api/v1/mail-accounts/google/callback|; s/^GOOGLE_CLIENT_SECRET=$/GOOGLE_CLIENT_SECRET="literal $() value"/' "${temp_dir}/custom.env"
rm -f "${temp_dir}/custom.env.bak"
PROVISION_ENV_FILE="${temp_dir}/custom.env" bash -c 'source ./provision; create_env; test "$(dotenv_get GOOGLE_CLIENT_SECRET "$ENV_FILE")" = "literal \$() value"'
grep -Fx 'GOOGLE_REDIRECT_URI=http://localhost:8181/api/v1/mail-accounts/google/callback' "${temp_dir}/custom.env"

if PROVISION_ENV_FILE="${temp_dir}/.env" bash -c 'source ./provision; docker(){ return 1; }; require_docker' >/dev/null 2>&1; then
  echo 'expected Docker prerequisite failure' >&2
  exit 1
fi

# Reject configurations that could target production containers or seed production.
cp "$env_file" "$temp_dir/unsafe.env"
for bad in 'COMPOSE_PROJECT_NAME=secureinbox' 'NODE_ENV=production' 'COMPOSE_PROFILES='; do
  cp "$env_file" "$temp_dir/unsafe.env"
  printf '%s\n' "$bad" >> "$temp_dir/unsafe.env"
  if PROVISION_ENV_FILE="$temp_dir/unsafe.env" bash -c 'source ./provision; load_runtime_values' >/dev/null 2>&1; then
    echo "Expected rejection: $bad" >&2
    exit 1
  fi
done

cp "$env_file" "$temp_dir/atlas.env"
printf '%s\n' 'COMPOSE_PROFILES=' 'DB_URI=mongodb+srv://example.test/secureinbox_test' >> "$temp_dir/atlas.env"
PROVISION_ENV_FILE="$temp_dir/atlas.env" bash -c 'source ./provision; load_runtime_values'
printf '%s\n' 'DB_URI=mongodb+srv://example.test/secureinbox' >> "$temp_dir/atlas.env"
if PROVISION_ENV_FILE="$temp_dir/atlas.env" bash -c 'source ./provision; load_runtime_values' >/dev/null 2>&1; then
  echo 'Expected rejection of production database in development' >&2
  exit 1
fi
