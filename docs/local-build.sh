#!/bin/bash

if [ ! -d venv ];then
  python3 -m venv venv
  source venv/bin/activate
  pip3 install -r requirements.txt
fi

source venv/bin/activate

export default_version=`git describe --abbrev=6 --dirty --always`
export versions="$default_version v9.2 v9.1 v9.0 nightly"
export current_version=$default_version

case $1 in
	"epub")
		sphinx-build -b epub . pdf
		;;
	*)
		sphinx-build -b html . www
		;;
esac


