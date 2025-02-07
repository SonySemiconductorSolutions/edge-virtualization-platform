#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

t=60

for i; do
    case "$1" in
    -p)
        plat=${2?'run-tests: missed platform'}
        shift 2
        ;;
    -t)
        t=${2?'run-test: missed timeout'}
        shift 2
        ;;
    -d)
        logdir=${2?'run-tests: missed log directory'}
        shift 2
        ;;
    -e)
        exec=${2?'run-tests: missed executor'}
        shift 2
        ;;
    -c)
        normal=`tput sgr0`
        pass=`tput setaf 2`
        fail=`tput setaf 1`
        shift
        ;;
    -s)
        serial=1
        shift
        ;;
    -*)
        echo 'run-tests.sh [-c][-s][-t time][-e exec][-p platform][-d logdir] tests...' >&2
        exit 1
        ;;
    *)
        break
    esac
done

mkdir -p ${logdir:=logs}
resfile=$logdir/run-$$.res

trap "kill -KILL 0 2>/dev/null" INT TERM HUP

export EVP_IOT_PLATFORM=${plat:=EVP1-TB}

run_test()
{
    set +e

    LLVM_PROFILE_FILE=$2.profraw timeout -k 5 $t $exec ./$1 > $2.log 2>&1

    res=$?
    case $res in
    124)
        echo "<<TIMEOUT>>"
        ;;
    137)
        echo "<<TIMEOUT not attended>>"
        ;;
    0)
        ;;
    *)
        echo "<<Error running test>> $res"
        ;;
    esac >> $2.log

    test $res -eq 0 &&
    printf ${pass}PASS${normal} ||
    printf ${fail}FAIL${normal} &&
    printf "\t%3s\t$1\n" $3
}

# As we run all the tests in parallel there is a chance we get some
# interleaving when they print the results, To avoid that and make the
# output more beatiful we use a file to ensure that we get full lines
for i
do
    export EVP_DATA_DIR=`mktemp -d -p $logdir`
    export EVP_AGENT_FIFO=$EVP_DATA_DIR/pipe
    name=$logdir/$i
    mkdir -p `dirname $name`
    (run_test $i $name $plat > $name.res; cat $name.res)&
    test  -n "$serial" && wait
done | tee $resfile
wait

test `grep -c FAIL $resfile` -eq 0
