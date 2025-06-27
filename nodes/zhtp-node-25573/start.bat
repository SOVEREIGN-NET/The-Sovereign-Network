@echo off
echo Starting ZHTP Node: zhtp-node-25573
set ZHTP_NODE_NAME=zhtp-node-25573
set ZHTP_NODE_TYPE=validator
set ZHTP_PORT=8080
zhtp-dev.exe --config config\node.json --port 8080
