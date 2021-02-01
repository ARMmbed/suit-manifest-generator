#!/bin/sh
RELPATH=$(dirname "$0")/..
ABSPATH=$(cd ${RELPATH} && pwd)
CURDIR=$(basename $(pwd))

docker run -v ${ABSPATH}:/suit -t suit-tool-image make -C /suit/${CURDIR}/docker-scripts