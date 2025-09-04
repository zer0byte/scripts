#!/bin/bash

# ASCII Art Banner
echo "======================================================"
echo "           Zer0byte's Enhanced Recon Script           "
echo "                         v5.0                        "
echo "======================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
MAX_PARALLEL_JOBS=10
TIMEOUT_SECONDS=300
OUTPUT_DIR="recon_results_$(date +%Y%m%d_%H%M%S)"

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

# Create main output directory with timestamp
mkdir -p "$OUTPUT_DIR"/{nmap,nikto,dirb,gobuster,eyewitness,whatweb,wafw00f,nuclei,wpscan,subdomains,screenshots,reports,logs}

# Function to log messages with timestamp
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/logs/main.log"
}

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
    log_message "[+] $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
    log_message "[-] $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_message "[!] $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
    log_message "[*] $1"
}

# Function to check tool availability
check_tool() {
    if command -v "$1" &> /dev/null; then
        print_status "$1 is available"
        return 0
    else
        print_warning "$1 is not installed"
        return 1
    fi
}

# Function to install missing tools (Debian/Ubuntu)
install_tools() {
    print_info "Checking and installing missing tools..."
    
    # Update package list
    sudo apt-get update -qq
    
    # Essential tools
    tools_apt="nmap nikto dirb gobuster whatweb wafw00f nuclei wpscan subfinder amass httpx waybackurls gau"
    for tool in $tools_apt; do
        if ! command -v "$tool" &> /dev/null; then
            print_info "Installing $tool..."
            sudo apt-get install -y "$tool" 2>/dev/null
        fi
    done
    
    # Install Go tools if Go is available
    if command -v go &> /dev/null; then
        go_tools=(
            "github.com/projectdiscovery/httpx/cmd/httpx@latest"
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            "github.com/tomnomnom/waybackurls@latest"
            "github.com/lc/gau/v2/cmd/gau@latest"
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        )
        
        for tool in "${go_tools[@]}"; do
            print_info "Installing Go tool: $tool"
            go install "$tool" 2>/dev/null
        done
    fi
}

# Function to find wordlists
find_wordlists() {
    # Common wordlists
    declare -A wordlists
    wordlists[common]="/usr/share/wordlists/dirb/common.txt"
    wordlists[medium]="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    wordlists[big]="/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
    wordlists[raft_large]="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt"
    
    # Alternative paths
    alt_paths=(
        "/usr/share/dirb/wordlists"
        "/usr/share/wordlists/dirb"
        "/usr/share/dirbuster/wordlists"
        "/usr/share/seclists"
    )
    
    for key in "${!wordlists[@]}"; do
        if [ -f "${wordlists[$key]}" ]; then
            eval "WORDLIST_$key=${wordlists[$key]}"
        else
            # Try alternative paths
            for alt_path in "${alt_paths[@]}"; do
                if [ -f "$alt_path/$(basename ${wordlists[$key]})" ]; then
                    eval "WORDLIST_$key=$alt_path/$(basename ${wordlists[$key]})"
                    break
                fi
            done
        fi
    done
    
    # Set default wordlist
    if [ -n "$WORDLIST_common" ]; then
        DEFAULT_WORDLIST="$WORDLIST_common"
    elif [ -n "$WORDLIST_medium" ]; then
        DEFAULT_WORDLIST="$WORDLIST_medium"
    else
        print_error "No suitable wordlist found. Please install dirb or dirbuster wordlists."
        return 1
    fi
    
    print_info "Default wordlist: $DEFAULT_WORDLIST"
}

# Function to read and validate targets
read_targets() {
    if [ -f "$1" ]; then
        # Read and clean targets
        mapfile -t target_array < <(tr -d '\r' < "$1" | grep -v '^$' | grep -v '^#')
        
        # Validate targets
        valid_targets=()
        for target in "${target_array[@]}"; do
            if [[ "$target" =~ ^https?:// ]] || [[ "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                valid_targets+=("$target")
            else
                print_warning "Skipping invalid target: $target"
            fi
        done
        
        target_array=("${valid_targets[@]}")
        print_info "Loaded ${#target_array[@]} valid targets"
    else
        print_error "File $1 not found."
        exit 1
    fi
}

# Function to start screen session with better error handling
start_screen_session() {
    local session_name=$1
    local command=$2
    local max_retries=3
    local retry_count=0
    
    # Check if screen session already exists
    if screen -list | grep -q "$session_name"; then
        print_warning "Screen session '$session_name' already exists. Skipping."
        return 1
    fi
    
    # Start session with retry logic
    while [ $retry_count -lt $max_retries ]; do
        if screen -dmS "$session_name" bash -c "$command; echo 'Scan completed. Press any key to exit.'; read"; then
            print_status "$session_name started successfully"
            sleep 1
            return 0
        else
            retry_count=$((retry_count + 1))
            print_warning "Failed to start $session_name (attempt $retry_count/$max_retries)"
            sleep 2
        fi
    done
    
    print_error "Failed to start $session_name after $max_retries attempts"
    return 1
}

# Enhanced subdomain enumeration
start_subdomain_enum() {
    print_info "Starting subdomain enumeration..."
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        # Extract domain from URL if needed
        domain=$(echo "$target" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        clean_domain=$(echo "$domain" | tr '.' '_')
        
        # Subfinder
        if command -v subfinder &> /dev/null; then
            start_screen_session "subfinder_$clean_domain" "subfinder -d $domain -o $OUTPUT_DIR/subdomains/subfinder_$clean_domain.txt -silent"
        fi
        
        # Amass
        if command -v amass &> /dev/null; then
            start_screen_session "amass_$clean_domain" "amass enum -passive -d $domain -o $OUTPUT_DIR/subdomains/amass_$clean_domain.txt"
        fi
        
        # Certificate transparency
        start_screen_session "crtsh_$clean_domain" "curl -s 'https://crt.sh/?q=%25.$domain&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > $OUTPUT_DIR/subdomains/crtsh_$clean_domain.txt"
    done
}

# Web technology detection
start_tech_detection() {
    print_info "Starting web technology detection..."
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        clean_target=$(echo "$target" | tr -d '/' | tr ':' '_' | tr '.' '_')
        
        # Add protocol if missing
        if [[ ! "$target" =~ ^https?:// ]]; then
            http_target="http://$target"
            https_target="https://$target"
        else
            http_target="$target"
            https_target=$(echo "$target" | sed 's/http:/https:/')
        fi
        
        # WhatWeb
        if command -v whatweb &> /dev/null; then
            start_screen_session "whatweb_$clean_target" "whatweb $http_target $https_target --log-brief $OUTPUT_DIR/whatweb/whatweb_$clean_target.txt"
        fi
        
        # WAF Detection
        if command -v wafw00f &> /dev/null; then
            start_screen_session "wafw00f_$clean_target" "wafw00f $http_target -o $OUTPUT_DIR/wafw00f/wafw00f_$clean_target.txt"
        fi
    done
}

# Enhanced directory/file enumeration
start_enhanced_dirb() {
    print_info "Starting enhanced directory enumeration..."
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        clean_target=$(echo "$target" | tr -d '/' | tr ':' '_' | tr '.' '_')
        
        # Add protocol if missing
        if [[ ! "$target" =~ ^https?:// ]]; then
            http_target="http://$target"
            https_target="https://$target"
        else
            http_target="$target"
            https_target=$(echo "$target" | sed 's/http:/https:/')
        fi
        
        # Gobuster (faster than dirb)
        if command -v gobuster &> /dev/null && [ -n "$DEFAULT_WORDLIST" ]; then
            start_screen_session "gobuster_http_$clean_target" "gobuster dir -u $http_target -w $DEFAULT_WORDLIST -t 50 -x php,html,txt,js,asp,aspx,jsp -o $OUTPUT_DIR/gobuster/gobuster_http_$clean_target.txt --timeout 10s"
            start_screen_session "gobuster_https_$clean_target" "gobuster dir -u $https_target -w $DEFAULT_WORDLIST -t 50 -x php,html,txt,js,asp,aspx,jsp -o $OUTPUT_DIR/gobuster/gobuster_https_$clean_target.txt --timeout 10s -k"
        fi
        
        # Original dirb for comparison
        if command -v dirb &> /dev/null && [ -n "$DEFAULT_WORDLIST" ]; then
            start_screen_session "dirb_http_$clean_target" "dirb $http_target $DEFAULT_WORDLIST -f -o $OUTPUT_DIR/dirb/dirb_http_$clean_target.txt"
            start_screen_session "dirb_https_$clean_target" "dirb $https_target $DEFAULT_WORDLIST -f -o $OUTPUT_DIR/dirb/dirb_https_$clean_target.txt"
        fi
    done
}

# Vulnerability scanning with Nuclei
start_nuclei_scan() {
    print_info "Starting Nuclei vulnerability scan..."
    
    if ! command -v nuclei &> /dev/null; then
        print_warning "Nuclei not found. Skipping vulnerability scan."
        return 1
    fi
    
    # Update nuclei templates
    nuclei -update-templates
    
    start_screen_session "nuclei_scan" "nuclei -l $target_file -o $OUTPUT_DIR/nuclei/nuclei_results.txt -severity critical,high,medium"
}

# WordPress scanning
start_wordpress_scan() {
    print_info "Starting WordPress enumeration..."
    
    if ! command -v wpscan &> /dev/null; then
        print_warning "WPScan not found. Skipping WordPress scan."
        return 1
    fi
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        clean_target=$(echo "$target" | tr -d '/' | tr ':' '_' | tr '.' '_')
        
        # Add protocol if missing
        if [[ ! "$target" =~ ^https?:// ]]; then
            target="http://$target"
        fi
        
        start_screen_session "wpscan_$clean_target" "wpscan --url $target --enumerate ap,at,cb,dbe --output $OUTPUT_DIR/wpscan/wpscan_$clean_target.txt --format cli"
    done
}

# Screenshot capture
start_screenshots() {
    print_info "Starting screenshot capture..."
    
    # Check for EyeWitness
    EYEWITNESS_PATHS=(
        "/opt/EyeWitness/Python/EyeWitness.py"
        "/root/Tools/EyeWitness/Python/EyeWitness.py"
        "$(which eyewitness 2>/dev/null)"
    )
    
    EYEWITNESS_CMD=""
    for path in "${EYEWITNESS_PATHS[@]}"; do
        if [ -f "$path" ] || [ "$path" != "" ]; then
            if [[ "$path" == *.py ]]; then
                EYEWITNESS_CMD="python3 $path"
            else
                EYEWITNESS_CMD="$path"
            fi
            break
        fi
    done
    
    if [ -n "$EYEWITNESS_CMD" ]; then
        start_screen_session "eyewitness_scan" "$EYEWITNESS_CMD --web -d $OUTPUT_DIR/eyewitness --prepend-https --no-prompt -f $target_file"
    else
        print_warning "EyeWitness not found. Skipping screenshot capture."
    fi
}

# Archive URL enumeration
start_archive_enum() {
    print_info "Starting archive URL enumeration..."
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        # Extract domain
        domain=$(echo "$target" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        clean_domain=$(echo "$domain" | tr '.' '_')
        
        # Wayback URLs
        if command -v waybackurls &> /dev/null; then
            start_screen_session "wayback_$clean_domain" "waybackurls $domain > $OUTPUT_DIR/subdomains/wayback_$clean_domain.txt"
        fi
        
        # GAU (GetAllUrls)
        if command -v gau &> /dev/null; then
            start_screen_session "gau_$clean_domain" "gau $domain > $OUTPUT_DIR/subdomains/gau_$clean_domain.txt"
        fi
    done
}

# Enhanced nmap scanning
start_enhanced_nmap() {
    print_info "Starting enhanced Nmap scans..."
    
    if ! command -v nmap &> /dev/null; then
        print_error "Nmap not found. Please install nmap."
        return 1
    fi
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        # Extract IP/domain from URL if needed
        clean_target=$(echo "$target" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        safe_name=$(echo "$clean_target" | tr '.' '_' | tr ':' '_')
        
        # Quick scan
        start_screen_session "nmap_quick_$safe_name" "nmap $clean_target -sV --top-ports 1000 --open -oA $OUTPUT_DIR/nmap/nmap_quick_$safe_name"
        
        # Full scan
        start_screen_session "nmap_full_$safe_name" "nmap $clean_target -sV -sC -p- --open -oA $OUTPUT_DIR/nmap/nmap_full_$safe_name"
        
        # UDP scan (top ports only)
        start_screen_session "nmap_udp_$safe_name" "nmap $clean_target -sU --top-ports 100 --open -oA $OUTPUT_DIR/nmap/nmap_udp_$safe_name"
    done
}

# Enhanced nikto scanning
start_enhanced_nikto() {
    print_info "Starting enhanced Nikto scans..."
    
    # Find nikto
    NIKTO_PATHS=(
        "$(which nikto 2>/dev/null)"
        "/root/Tools/nikto/program/nikto.pl"
        "/opt/nikto/program/nikto.pl"
    )
    
    NIKTO_CMD=""
    for path in "${NIKTO_PATHS[@]}"; do
        if [ -f "$path" ] || [ "$path" != "" ]; then
            NIKTO_CMD="$path"
            break
        fi
    done
    
    if [ -z "$NIKTO_CMD" ]; then
        print_error "Nikto not found. Please install nikto."
        return 1
    fi
    
    for target in "${target_array[@]}"; do
        [ -z "$target" ] && continue
        
        clean_target=$(echo "$target" | tr -d '/' | tr ':' '_' | tr '.' '_')
        
        # Add protocol if missing
        if [[ ! "$target" =~ ^https?:// ]]; then
            http_target="http://$target"
            https_target="https://$target"
        else
            http_target="$target"
            https_target=$(echo "$target" | sed 's/http:/https:/')
        fi
        
        start_screen_session "nikto_http_$clean_target" "$NIKTO_CMD -h $http_target -404code 301 -C all -timeout 120 -output $OUTPUT_DIR/nikto/nikto_http_$clean_target.txt"
        start_screen_session "nikto_https_$clean_target" "$NIKTO_CMD -h $https_target -404code 301 -C all -timeout 120 -output $OUTPUT_DIR/nikto/nikto_https_$clean_target.txt"
    done
}

# Generate summary report
generate_report() {
    print_info "Generating summary report..."
    
    REPORT_FILE="$OUTPUT_DIR/reports/summary_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Recon Summary Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .tool-results { background-color: #f9f9f9; padding: 10px; border-left: 4px solid #007cba; }
        .critical { color: #d9534f; font-weight: bold; }
        .high { color: #f0ad4e; font-weight: bold; }
        .medium { color: #5bc0de; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Application Reconnaissance Report</h1>
        <p>Generated on: $(date)</p>
        <p>Output Directory: $OUTPUT_DIR</p>
        <p>Targets: ${#target_array[@]}</p>
    </div>

    <div class="section">
        <h2>Target List</h2>
        <ul>
EOF

    for target in "${target_array[@]}"; do
        echo "            <li>$target</li>" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" << EOF
        </ul>
    </div>

    <div class="section">
        <h2>Tools Executed</h2>
        <div class="tool-results">
            <h3>Network Scanning</h3>
            <p>• Nmap: Port scanning and service detection</p>
            
            <h3>Web Application Scanning</h3>
            <p>• Nikto: Web server scanner</p>
            <p>• Dirb/Gobuster: Directory enumeration</p>
            <p>• Nuclei: Vulnerability scanner</p>
            
            <h3>Technology Detection</h3>
            <p>• WhatWeb: Web technology fingerprinting</p>
            <p>• Wafw00f: Web Application Firewall detection</p>
            
            <h3>Content Discovery</h3>
            <p>• EyeWitness: Screenshot capture</p>
            <p>• Subfinder/Amass: Subdomain enumeration</p>
            <p>• WaybackURLs/GAU: Archive URL discovery</p>
            
            <h3>CMS Specific</h3>
            <p>• WPScan: WordPress vulnerability scanner</p>
        </div>
    </div>

    <div class="section">
        <h2>Output Directories</h2>
        <ul>
            <li><strong>nmap/</strong> - Network scan results</li>
            <li><strong>nikto/</strong> - Web vulnerability scan results</li>
            <li><strong>dirb/</strong> - Directory enumeration results</li>
            <li><strong>gobuster/</strong> - Enhanced directory enumeration</li>
            <li><strong>nuclei/</strong> - Automated vulnerability scan results</li>
            <li><strong>whatweb/</strong> - Technology fingerprinting results</li>
            <li><strong>wafw00f/</strong> - WAF detection results</li>
            <li><strong>wpscan/</strong> - WordPress scan results</li>
            <li><strong>subdomains/</strong> - Subdomain enumeration and archive URLs</li>
            <li><strong>eyewitness/</strong> - Screenshots and visual reconnaissance</li>
            <li><strong>logs/</strong> - Execution logs</li>
            <li><strong>reports/</strong> - Summary reports</li>
        </ul>
    </div>

    <div class="section">
        <h2>Next Steps</h2>
        <ul>
            <li>Review all output files for interesting findings</li>
            <li>Investigate any high/critical vulnerabilities found</li>
            <li>Manual testing of discovered directories and files</li>
            <li>Deep dive into specific services found during port scans</li>
            <li>Subdomain takeover verification</li>
        </ul>
    </div>
</body>
</html>
EOF

    print_status "Report generated: $REPORT_FILE"
}

# Session management functions
show_sessions() {
    echo ""
    print_info "Current screen sessions:"
    screen -list | grep -E "(dirb_|nikto_|nmap_|eyewitness_|gobuster_|nuclei_|whatweb_|wafw00f_|subfinder_|amass_|wayback_|gau_|wpscan_)" || echo "No reconnaissance sessions running."
    echo ""
}

kill_all_sessions() {
    print_info "Killing all reconnaissance screen sessions..."
    for session in $(screen -list | grep -E "(dirb_|nikto_|nmap_|eyewitness_|gobuster_|nuclei_|whatweb_|wafw00f_|subfinder_|amass_|wayback_|gau_|wpscan_)" | cut -d. -f1 | awk '{print $1}'); do
        screen -S "$session" -X quit
        print_status "Killed session: $session"
    done
}

# Monitor progress
monitor_progress() {
    while true; do
        active_sessions=$(screen -list | grep -cE "(dirb_|nikto_|nmap_|eyewitness_|gobuster_|nuclei_|whatweb_|wafw00f_|subfinder_|amass_|wayback_|gau_|wpscan_)")
        
        if [ "$active_sessions" -eq 0 ]; then
            print_status "All scans completed!"
            generate_report
            break
        else
            print_info "$active_sessions active scan sessions running..."
            sleep 30
        fi
    done
}

# Initialize
print_info "Initializing enhanced recon script..."
find_wordlists
read_targets "$target_file"

# Main menu
while true; do
    echo ""
    echo -e "${CYAN}=== Enhanced Recon Menu ===${NC}"
    echo "1)  Quick Scan (Nmap + Dirb + Nikto)"
    echo "2)  Full Enumeration (All tools)"
    echo "3)  Network Scanning (Nmap only)"
    echo "4)  Web Scanning (Nikto + Dirb + Gobuster)"
    echo "5)  Directory Enumeration (Dirb + Gobuster)"
    echo "6)  Vulnerability Scanning (Nuclei)"
    echo "7)  Technology Detection (WhatWeb + Wafw00f)"
    echo "8)  Content Discovery (Screenshots + Archives)"
    echo "9)  Subdomain Enumeration"
    echo "10) WordPress Scanning"
    echo "11) Custom Tool Selection"
    echo "12) Show Running Sessions"
    echo "13) Kill All Sessions"
    echo "14) Monitor Progress"
    echo "15) Generate Report"
    echo "16) Install Missing Tools"
    echo "17) Exit"
    echo ""

    read -p "Enter your choice [1-17]: " choice

    case $choice in
        1)
            print_info "Starting quick scan..."
            start_enhanced_nmap
            start_enhanced_dirb
            start_enhanced_nikto
            ;;
        2)
            print_info "Starting full enumeration..."
            start_enhanced_nmap
            start_enhanced_nikto
            start_enhanced_dirb
            start_nuclei_scan
            start_tech_detection
            start_screenshots
            start_subdomain_enum
            start_archive_enum
            start_wordpress_scan
            ;;
        3)
            start_enhanced_nmap
            ;;
        4)
            start_enhanced_nikto
            start_enhanced_dirb
            ;;
        5)
            start_enhanced_dirb
            ;;
        6)
            start_nuclei_scan
            ;;
        7)
            start_tech_detection
            ;;
        8)
            start_screenshots
            start_archive_enum
            ;;
        9)
            start_subdomain_enum
            ;;
        10)
            start_wordpress_scan
            ;;
        11)
            # Custom tool selection submenu
            echo "Select tools to run:"
            echo "a) Nmap  b) Nikto  c) Dirb  d) Gobuster  e) Nuclei"
            echo "f) WhatWeb  g) Wafw00f  h) Screenshots  i) Subdomains  j) WordPress"
            read -p "Enter letters (e.g., abc): " tools
            
            [[ "$tools" =~ a ]] && start_enhanced_nmap
            [[ "$tools" =~ b ]] && start_enhanced_nikto
            [[ "$tools" =~ c ]] && { start_enhanced_dirb; }
            [[ "$tools" =~ d ]] && start_enhanced_dirb
            [[ "$tools" =~ e ]] && start_nuclei_scan
            [[ "$tools" =~ f ]] && start_tech_detection
            [[ "$tools" =~ g ]] && start_tech_detection
            [[ "$tools" =~ h ]] && start_screenshots
            [[ "$tools" =~ i ]] && start_subdomain_enum
            [[ "$tools" =~ j ]] && start_wordpress_scan
            ;;
        12)
            show_sessions
            ;;
        13)
            kill_all_sessions
            ;;
        14)
            monitor_progress
            ;;
        15)
            generate_report
            ;;
        16)
            install_tools
            ;;
        17)
            print_info "Exiting the script."
            exit 0
            ;;
        *)
            print_error "Invalid choice. Please select a valid option."
            ;;
    esac
done
