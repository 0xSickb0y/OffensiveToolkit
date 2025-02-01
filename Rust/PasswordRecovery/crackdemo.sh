#!/bin/bash

wordlist_path="$1"

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/wordlist"
    exit 1
fi

if [ ! -f "$wordlist_path" ]; then
    echo "Error: File not found or cannot be opened: $wordlist_path"
    exit 1
fi

start_time=$(date +%s%3N)

for file in hashes/*_hashes.txt; do
    algo=$(basename "$file" "_hashes.txt")

    printf "\n====================\n"
    printf "Starting process for: \033[1;32m$algo\033[0m"
    printf "\n====================\n"

    cargo run --quiet "$algo" "$file" "$wordlist_path"
done

end_time=$(date +%s%3N)

elapsed_time_ms=$((end_time - start_time))

elapsed_time_sec=$((elapsed_time_ms / 1000))
elapsed_time_min=$((elapsed_time_sec / 60))
elapsed_time_hour=$((elapsed_time_min / 60))

if [ $elapsed_time_hour -gt 0 ]; then
    printf "\nProcess completed in: \033[1;32m$elapsed_time_hour hours, $((elapsed_time_min % 60)) minutes, $((elapsed_time_sec % 60)) seconds\033[0m.\n\n"
elif [ $elapsed_time_min -gt 0 ]; then
    printf "\nProcess completed in: \033[1;32m$elapsed_time_min minutes, $((elapsed_time_sec % 60)) seconds\033[0m.\n\n"
else
    printf "\nProcess completed in: \033[1;32m$elapsed_time_sec seconds\033[0m.\n\n"
fi
