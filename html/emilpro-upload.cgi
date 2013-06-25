#!/bin/sh

echo "Content-Type: text/xml"
echo ""

DIR=/home/ska/emilpro/server-data

PID=1

if [ -f $DIR/server.pid ]; then
	PID=`cat $DIR/server.pid`
fi

# Start server if needed
kill -0 $PID 2> /dev/null
if [ $? -ne 0 ] ; then
	/home/ska/emilpro/cgi-server $DIR
fi

exec /www/emilpro/cgi-bin/emilpro-upload.cgi.real $DIR/to-server.fifo $DIR/from-server.fifo
