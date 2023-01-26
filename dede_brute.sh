#!/bin/bash

serv=$(cat servers.txt | wc -l)
serv=$((serv+1))

thread=5


es=$(awk 'BEGIN {print '$serv' / '$thread';}')
gap=$([[ $es =~ '.' ]] && echo $((${es%.*} + 1)) || echo $es)

sudo split servers.txt server -a 1 -d -l $gap

FILE=./server
if [ -d "$FILE" ]; then
    :
else
mkdir server
fi

ls | grep -e 'server[0-9]' | xargs mv -t ./server

iter=$(echo "$(ls ./server | wc -l)")
iter=$((iter-1))

function start_python() {
	sudo python3 dedecms_bruteforce.py -s server$i -l log$i -r result$i -e error$i
}


for ((i=0; i<=$iter; i++))
do
	start_python "$i" &
done
wait