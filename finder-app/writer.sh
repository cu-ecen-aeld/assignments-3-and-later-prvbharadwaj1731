#!/bin/bash

#filename: writer.sh
#Author: Pranav Bharadwaj
#Date: 08/28/2022

#Check if all input arguments are provided

if [ ! $# -eq 2 ]; then
	echo "Required number of parameters not specified"
	exit 1
fi

# Store input arguments in variables
WRITE_FILE=$1
WRITE_STR=$2

# create file if it does not exist, else overwrite it (using redirection operator)
echo "$WRITE_STR" > "$WRITE_FILE"

