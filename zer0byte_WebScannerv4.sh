#!/bin/bash

# ASCII Art Banner
echo "======================================================"
echo "                Zer0byte's Recon Script               "
echo "                         v4                          "
echo "======================================================"
echo ""

# Check if a targets file path was provided as an argument
if [ -z "$1" ]; then
  read -p "Please provide the path to the targets file: " target_file
  if [ -z "$target_file" ]; then
    echo "No file name provided. Exiting."
    exit 1
  fi
else
  target_file="$1"
fi

# Function to check and read targets from a file
read_targets() {
  if [ -f "$1" ]; then
    targets=$(cat "$1")
  else
    echo "File $1 not found."
    exit 1
  fi
}

# Read the targets from the target file
read_targets "$target_file"

# Function to start a screen session with a given name and command
start_screen_session() {
  session_name=$1
  command=$2

  screen -dmS "$session_name" bash -c "$command"
  echo "$session_name has started."
}

# Create directories for the results if they don't exist
mkdir -p results/nmap results/nikto results/dirb results/eyewitness

# Function to start dirb scans
start_dirb_scans() {
  for target in $targets; do
    clean_target=$(echo $target | tr -d '/')
    http_target="http://$target"
    https_target="https://$target"
    start_screen_session "dirb_http_$clean_target" "dirb $http_target /root/common.txt -f -o results/dirb/dirb_http_$clean_target.txt"
    start_screen_session "dirb_https_$clean_target" "dirb $https_target /root/common.txt -f -o results/dirb/dirb_https_$clean_target.txt"
  done
}

# Function to start nikto scans
start_nikto_scans() {
  for target in $targets; do
    clean_target=$(echo $target | tr -d '/')
    http_target="http://$target"
    https_target="https://$target"
    start_screen_session "nikto_http_$clean_target" "/root/Tools/nikto/program/nikto.pl -h $http_target -404code 301 -C all -output results/nikto/nikto_http_$clean_target.txt"
    start_screen_session "nikto_https_$clean_target" "/root/Tools/nikto/program/nikto.pl -h $https_target -404code 301 -C all -output results/nikto/nikto_https_$clean_target.txt"
  done
}

# Function to start nmap scans
start_nmap_scans() {
  for target in $targets; do
    clean_target=$(echo $target | tr -d '/')
    start_screen_session "nmap_$clean_target" "nmap $target -sV --open -oA results/nmap/nmap_$clean_target"
  done
}

# Function to start EyeWitness scans
start_eyewitness_scans() {
  start_screen_session "eyewitness_scan" "python3 /root/Tools/EyeWitness/Python/EyeWitness.py --web -d results/eyewitness --prepend-https --no-prompt -f $target_file"
}

# Menu
while true; do
  echo "Please choose an option:"
  echo "1) Start dirb only"
  echo "2) Start nikto only"
  echo "3) Start nmap only"
  echo "4) Start EyeWitness only"
  echo "5) Start all scans"
  echo "6) Exit"

  read -p "Enter your choice [1-6]: " choice

  case $choice in
    1)
      start_dirb_scans
      ;;
    2)
      start_nikto_scans
      ;;
    3)
      start_nmap_scans
      ;;
    4)
      start_eyewitness_scans
      ;;
    5)
      start_dirb_scans
      start_nikto_scans
      start_nmap_scans
      start_eyewitness_scans
      ;;
    6)
      echo "Exiting the script."
      exit 0
      ;;
    *)
      echo "Invalid choice. Please select a valid option."
      ;;
  esac
done

echo "All selected screen sessions started."

