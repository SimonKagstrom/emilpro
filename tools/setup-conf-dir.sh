#!/bin/sh

if [ $# -lt 2 ] ; then
    echo "Usage: setup-conf-dir.sh <out-directory> <remote/local> <timestamp> [insn-name timestamp]"
    exit 1
fi

DIR=$1
TYPE=$2
TS=$3

install -d $DIR
install -d $DIR/remote
install -d $DIR/local
install -d $DIR/configuration

shift; shift; shift

while [ $# -gt 1 ] ; do
    NAME=$1
    INSN_TS=$2

    cat <<EOF > $DIR/$TYPE/${NAME}.xml
<?xml version="1.0" encoding="UTF-8"?>
<emilpro>
  <InstructionModel name="$NAME" architecture="mips" timestamp="$INSN_TS">
     <description>~_lessr;~b~_great;~INGOLF~_lessr;~/b~_great;~</description>
  </InstructionModel>
</emilpro>
EOF

    shift ; shift
done


if [ $TS -eq 0 ] ; then
    exit 0
fi

cat << EOF > $DIR/remote/serverTimestamp.xml
<?xml version="1.0" encoding="UTF-8"?>
<emilpro>
  <ServerTimestamps>
     <InstructionModelTimestamp>$TS</InstructionModelTimestamp>
  </ServerTimestamps>
</emilpro>
EOF
