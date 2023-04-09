#!/bin/bash
meson _complexity
cd _complexity
run-clang-tidy-$VERSION -quiet \
    -config="{Checks: 'readability-function-cognitive-complexity', CheckOptions: [{key: readability-function-cognitive-complexity.Threshold, value: 25}, {key: readability-function-cognitive-complexity.DescribeBasicIncrements, value: False}]}" \
    2>/dev/null | \
    grep warning | grep "cognitive complexity" > complexity.log || :

complexity=0
complex_functions=0
while read -r log; do
    file=$(echo $log | awk -F":" '{ print $1 }')
    line=$(echo $log | awk -F":" '{ print $2 }')
    function=$(echo $log | awk -F"function" '{ print $2 }' | awk '{ print $1 }' | sed "s/'//g")
    score=$(echo $log | awk -F"cognitive complexity of" '{ print $2 }' | awk '{ print $1 }')

    echo "Complex function found: $file:$line $function(), complexity score: $score"

    complexity=$(( complexity + score ))
    (( complex_functions++ )) || :
done < complexity.log
mv complexity.log ..
cd ..
rm -rf _complexity

echo "Found $complex_functions complex functions"
echo "Final complexity sum of complex functions: $complexity"

echo "Functions: $complex_functions" >> complexity.log
echo "Sum: $complexity" >> complexity.log
