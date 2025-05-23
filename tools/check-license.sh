#! /bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

FILES=$@

# Use the absolute paths to workaround the issue:
#    https://github.com/actions/runner/issues/765
#    https://github.com/actions/runner/issues/659
WD=$(pwd -P)
OFILES="$FILES"
FILES=
for F in $OFILES; do
    FILES="$FILES ${WD}/${F}"
done
# All files have to start with the license comment
LICENSE_OK=1
N_FILES=0
for file_test in $FILES; do
    # ignore directories or empty files
    if [ ! -f $file_test ] || [ ! -s "$file_test" ]; then
        continue
    fi

# REUSE-IgnoreStart
    COPYRIGHT_PRESENT=$( grep -E 'SPDX-FileCopyrightText: [0-9]{4}(-[0-9]{4})? Sony Semiconductor Solutions Corporation' -c $file_test || :)
    LICENSE_IS_APACHE=$( grep -F "SPDX-License-Identifier: Apache-2.0" -c $file_test || :)
# REUSE-IgnoreEnd

    if [ "${FIRST_LINE_COMMENT}" = "0" -o "${LICENSE_IS_APACHE}" = "0" -o "${COPYRIGHT_PRESENT}" = "0" ]; then
        FILES_TO_UPDATE="${FILES_TO_UPDATE} ${file_test}"
        # Check all files before exiting
        LICENSE_OK=0
    fi
    N_FILES=$((${N_FILES} + 1))
done

if [ $LICENSE_OK -eq 0 ]; then
    echo "INVALID LICENSE HEADER: Please check copyright notices in:"
    for update in $FILES_TO_UPDATE; do
        UPDATTE_N_FILES=$((${UPDATTE_N_FILES} + 1))
        echo "${update}"
    done
    echo "Total files to review ${UPDATTE_N_FILES}"
    exit 1
fi

echo total files checked ${N_FILES}
