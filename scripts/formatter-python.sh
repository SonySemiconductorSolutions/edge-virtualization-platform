#! /bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# formatter or checker (run as checker-python.sh) for python files
#
# Input variables:
#   EXCLUDE_NAMES: List of csv of exluce files/directory names
#
# Expected usage:
#   To format files > EXCLUDE_NAMES="local_test" ./formatter-python.sh
#   To check files  > EXCLUDE_NAMES="local_test" ./checker-python.sh

set -e

if [ -n "${EXCLUDE_NAMES}" ]; then
    SEP=","
else
    SEP=""
fi

EXCLUDE_NAMES="${EXCLUDE_NAMES}${SEP}stage"
EXCLUDE_NAMES="${EXCLUDE_NAMES},.doc-venv"
EXCLUDE_NAMES="${EXCLUDE_NAMES},.git"
EXCLUDE_NAMES="${EXCLUDE_NAMES},depend"
EXCLUDE_NAMES="${EXCLUDE_NAMES},build"

# Exclude submodules files
EXCLUDE_NAMES="${EXCLUDE_NAMES},src/flatcc"
EXCLUDE_NAMES="${EXCLUDE_NAMES},src/mbedtls"
EXCLUDE_NAMES="${EXCLUDE_NAMES},src/nuttx"
EXCLUDE_NAMES="${EXCLUDE_NAMES},src/nuttx-apps"
EXCLUDE_NAMES="${EXCLUDE_NAMES},src/wasm-micro-runtime"

# black is using "|" as a separator, instead of "," used by pycodestyle
# Also black checks .gitignore to exclude files
BLACK_EXCLUDE_NAMES=$(echo $EXCLUDE_NAMES | tr "," "|")
BLACK_LINE_ARG="--line-length 79"
PYCODESTYLE_LINE_ARG="--ignore=E203,W503"
FLAKE8_LINE_ARG="--extend-ignore=E203"

# formatter python
if [ "$(basename $0)" = "formatter-python.sh" ]; then
    # Note: --line-length 79 for black is intended to match the default of
    # pycodestyle.
    black --exclude $BLACK_EXCLUDE_NAMES $BLACK_LINE_ARG .
fi

echo "Checking filename scripts has valid format..."
FILENAME_EXCLUDE_FOLDERS=$(echo $EXCLUDE_NAMES | tr "," " ")

PYTHON_FILES=$(git ls-files | grep '\.py$')

for file in ${PYTHON_FILES}; do
    NAME_PY=$(basename ${file})
    HYPHEN_FOUND=$(echo ${NAME_PY} | grep '-' | wc -l)
    if [ $HYPHEN_FOUND != 0 ]; then
        printf "Hyphen in filename: %s\n" ${NAME_PY}
        exit 1
    fi
done
echo "Filename scripts are valid. OK!"

echo "Checking python code format and style"
black  --check --exclude  $BLACK_EXCLUDE_NAMES $BLACK_LINE_ARG ${PYTHON_FILES}
pycodestyle ${PYTHON_FILES} --exclude=$EXCLUDE_NAMES $PYCODESTYLE_LINE_ARG
flake8 ${PYTHON_FILES} --exclude=$EXCLUDE_NAMES $FLAKE8_LINE_ARG
echo "Python code format and style are valid. OK!"
