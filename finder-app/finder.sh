#!/bin/sh

#filename: finder.sh
#Author: Pranav Bharadwaj
#Date: 08/28/2022

#Check if all input arguments are provided

if [ ! $# -eq 2 ]; then
	echo "Required number of parameters not specified"
	exit 1
fi	
	
#Store arguments in local variables

FILES_DIR=$1
SEARCH_STR=$2

#Check if file directory provided exists

if [ ! -d "$FILES_DIR" ]; then
        echo "Error: ${FILES_DIR} not found. Exiting..."
        exit 1
fi

#Count number of files present in given path and all subsequent subdirectories
FILE_COUNT="$(find "$FILES_DIR" -type f | wc -l)"

#Search for string recursively in path provided
LINE_COUNT="$(grep -r "$SEARCH_STR" "$FILES_DIR" | wc -l)"

echo "The number of files are ${FILE_COUNT} and the number of matching lines are ${LINE_COUNT}"


