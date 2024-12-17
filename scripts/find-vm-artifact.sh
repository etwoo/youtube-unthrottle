#!/usr/bin/env sh

set -euo pipefail

TARGET="$1"
ARTIFACT_SIZE_MINIMUM=800000000

#
# Some helpful GitLab API references:
#
#   https://docs.gitlab.com/ee/api/personal_access_tokens.html
#   https://docs.gitlab.com/ee/api/jobs.html
#   https://docs.gitlab.com/ee/api/job_artifacts.html
#
JOBS_URI="https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/jobs"
JQ_FILTER="map(select(.artifacts_file.size > $ARTIFACT_SIZE_MINIMUM)) | .[].id"

#
# Options to use with curl invocations:
#
# --fail: treat any 4xx or 5xx status codes as fatal for this script as a whole
#
# --silent: suppress any progress bars or debug output
#
# -L, aka --location: follow any 3xx redirects
#
# -H, aka --header: use $CI_PERSONAL_ACCESS_TOKEN for GitLab authN/authZ
#
CURL_OPTS=(--fail --silent -L -H "PRIVATE-TOKEN:$CI_PERSONAL_ACCESS_TOKEN")

i=0
while [ $((i++)) ] ; do
	job_json=$(curl "${CURL_OPTS[@]}" "$JOBS_URI?page=$i&per_page=100")
	if [ "$job_json" == "[]" ] ; then
		# Reached the last page of jobs; stop looking and error out.
		break
	fi

	job_candidates=$(echo "$job_json" | jq "$JQ_FILTER")
	if [ -z "$job_candidates" ] ; then
		echo "DEBUG: page $i has no artifacts of required size" >&2
		continue
	fi

	for job_id in $job_candidates ; do
		url_candidate="$JOBS_URI/$job_id/artifacts"
		url_target="$url_candidate/$TARGET"
		if curl --head "${CURL_OPTS[@]}" "$url_target" >/dev/null ; then
			echo "DEBUG: successful probe on $url_target" >&2
			echo "DEBUG: returning $url_candidate" >&2
			echo "$url_candidate"
			exit 0
		fi
		echo "DEBUG: $url_candidate does not contain $TARGET" >&2
	done

	echo "DEBUG: page $i has no artifacts with matching image name" >&2
done

echo "ERROR: Cannot find a suitable job" >&2
exit 1
