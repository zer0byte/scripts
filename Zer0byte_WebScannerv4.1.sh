#!/bin/bash

# ASCII Art Banner
echo "======================================================"
echo "                Zer0byte's Recon Script               "
echo "                         v4.1 (Fixed)                "
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

# Function to find the correct wordlist path
find_wordlist() {
  local wordlists=(
    "/usr/share/dirb/wordlists/common.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/root/common.txt"
  )
  
  for wordlist in "${wordlists[@]}"; do
    if [ -f "$wordlist" ]; then
      echo "$wordlist"
      return 0
    fi
  done
  
  echo "ERROR: No suitable wordlist found. Please install dirb or dirbuster wordlists."
  echo "Try: apt-get install dirb dirbuster"
  exit 1
}

# Get the wordlist path
WORDLIST=$(find_wordlist)
echo "Using wordlist: $WORDLIST"
echo ""

# Function to check and read targets from a file
read_targets() {
  if [ -f "$1" ]; then
    # Read targets into array, handling different line endings
    mapfile -t target_array < <(tr -d '\r' < "$1" | grep -v '^$')
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

  # Check if screen session already exists
  if screen -list | grep -q "$session_name"; then
    echo "Screen session '$session_name' already exists. Skipping."
    return 1
  fi

  screen -dmS "$session_name" bash -c "$command; echo 'Scan completed. Press any key to exit.'; read"
  echo "$session_name has started."
  sleep 1  # Brief pause to prevent overwhelming the system
}

# Create directories for the results if they don't exist
mkdir -p results/nmap results/nikto results/dirb results/eyewitness

# Function to start dirb scans
start_dirb_scans() {
  echo "Starting dirb scans..."
  for target in "${target_array[@]}"; do
    # Skip empty lines
    [ -z "$target" ] && continue
    
    clean_target=$(echo "$target" | tr -d '/' | tr ':' '_')
    http_target="http://$target"
    https_target="https://$target"
    
    start_screen_session "dirb_http_$clean_target" "dirb $http_target $WORDLIST -f -o results/dirb/dirb_http_$clean_target.txt"
    start_screen_session "dirb_https_$clean_target" "dirb $https_target $WORDLIST -f -o results/dirb/dirb_https_$clean_target.txt"
  done
}

# Function to start nikto scans
start_nikto_scans() {
  echo "Starting nikto scans..."
  
  # Check if nikto is available
  if ! command -v nikto &> /dev/null; then
    echo "Nikto not found. Trying alternative path..."
    NIKTO_CMD="/root/Tools/nikto/program/nikto.pl"
    if [ ! -f "$NIKTO_CMD" ]; then
      echo "ERROR: Nikto not found. Please install nikto or check the path."
      return 1
    fi
  else
    NIKTO_CMD="nikto"
  fi
  
  for target in "${target_array[@]}"; do
    # Skip empty lines
    [ -z "$target" ] && continue
    
    clean_target=$(echo "$target" | tr -d '/' | tr ':' '_')
    http_target="http://$target"
    https_target="https://$target"
    
    start_screen_session "nikto_http_$clean_target" "$NIKTO_CMD -h $http_target -404code 301 -C all -output results/nikto/nikto_http_$clean_target.txt"
    start_screen_session "nikto_https_$clean_target" "$NIKTO_CMD -h $https_target -404code 301 -C all -output results/nikto/nikto_https_$clean_target.txt"
  done
}

# Function to start nmap scans
start_nmap_scans() {
  echo "Starting nmap scans..."
  
  # Check if nmap is available
  if ! command -v nmap &> /dev/null; then
    echo "ERROR: Nmap not found. Please install nmap."
    return 1
  fi
  
  for target in "${target_array[@]}"; do
    # Skip empty lines
    [ -z "$target" ] && continue
    
    clean_target=$(echo "$target" | tr -d '/' | tr ':' '_')
    start_screen_session "nmap_$clean_target" "nmap $target -sV --open -oA results/nmap/nmap_$clean_target"
  done
}

# Function to start EyeWitness scans
start_eyewitness_scans() {
  echo "Starting EyeWitness scan..."
  
  # Check if EyeWitness is available
  EYEWITNESS_CMD="/root/Tools/EyeWitness/Python/EyeWitness.py"
  if [ ! -f "$EYEWITNESS_CMD" ]; then
    if command -v eyewitness &> /dev/null; then
      EYEWITNESS_CMD="eyewitness"
    else
      echo "ERROR: EyeWitness not found. Please install EyeWitness or check the path."
      return 1
    fi
  else
    EYEWITNESS_CMD="python3 $EYEWITNESS_CMD"
  fi
  
  start_screen_session "eyewitness_scan" "$EYEWITNESS_CMD --web -d results/eyewitness --prepend-https --no-prompt -f $target_file"
}

# Function to show running sessions
show_sessions() {
  echo ""
  echo "Current screen sessions:"
  screen -list | grep -E "(dirb_|nikto_|nmap_|eyewitness_)" || echo "No reconnaissance sessions running."
  echo ""
}

# Function to kill all recon sessions
kill_all_sessions() {
  echo "Killing all reconnaissance screen sessions..."
  for session in $(screen -list | grep -E "(dirb_|nikto_|nmap_|eyewitness_)" | cut -d. -f1 | awk '{print $1}'); do
    screen -S "$session" -X quit
    echo "Killed session: $session"
  done
}

# Menu
while true; do
  echo "Please choose an option:"
  echo "1) Start dirb only"
  echo "2) Start nikto only"
  echo "3) Start nmap only"
  echo "4) Start EyeWitness only"
  echo "5) Start all scans"
  echo "6) Show running sessions"
  echo "7) Kill all sessions"
  echo "8) Exit"

  read -p "Enter your choice [1-8]: " choice

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
      show_sessions
      ;;
    7)
      kill_all_sessions
      ;;
    8)
      echo "Exiting the script."
      exit 0
      ;;
    *)
      echo "Invalid choice. Please select a valid option."
      ;;
  esac
done

echo "All selected screen sessions started."
