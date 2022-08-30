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

# Check if path provided exists. Create file if it does not exist, else overwrite it (using redirection operator)
# If file does not exist or could not be created, return exit 1. Use try-catch to implement this, using || operator

{
	if [ ! -d "$WRITE_FILE" ];
	then
		#create path and create file and write string to it
		mkdir -p "$(dirname $WRITE_FILE)" && echo "$WRITE_STR" > "$WRITE_FILE"
	else
		echo "$WRITE_STR" > "$WRITE_FILE"
	fi
} || 
{
	echo "File cannot be created. Exiting..."
	exit 1
}

echo "$WRITE_STR" > "$WRITE_FILE"

