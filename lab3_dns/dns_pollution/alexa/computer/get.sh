#!/bin/bash

for ((i=0;i<=19;i++))
do
    echo $i
    curl ${ARGS} "https://www.alexa.com/topsites/category;${i}/Top/Computers" -o ${i}.html # secrets removed
done