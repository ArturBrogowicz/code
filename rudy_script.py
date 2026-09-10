#!/bin/bash
while true; do
    wrk -t2 -c50 -d2s http://10.0.0.1/ > /dev/null 2>&1
    sleep 6
done
