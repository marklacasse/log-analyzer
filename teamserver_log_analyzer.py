#!/usr/bin/env python3
"""
Teamserver Log Analyzer v2.0.0
Groups and counts common error, warn, info messages from Contrast Security TeamServer logs.
Outputs results in CSV format and provides command-line summary with key insights.
Now with baseline comparison support for anomaly detection and trend analysis.
"""

import re
import csv
import sys
import os
import json
from collections import Counter, defaultdict

def parse_log_line(line):
    """Parse a single log line and extract components"""
    # Skip stack trace lines and empty lines
    if line.strip().startswith('at ') or line.strip().startswith('Caused by:') or not line.strip():
        return None
    
    # Pattern to match: DATE TIME {Hash} {source} {} LEVEL (SOURCEFILE:LINE#) {message details}
    pattern = r'^(\d{6} \d{2}\.\d{2}\.\d{2},\d{3}) \{([^}]*)\} \{([^}]*)\} \{([^}]*)\} (ERROR|WARN|INFO)\s+\(([^)]+)\) (.*)$'
    
    match = re.match(pattern, line)
    if match:
        datetime_str, hash_val, source, empty_field, level, source_file, message_details = match.groups()
        return {
            'datetime': datetime_str,
            'hash': hash_val,
            'source': source,
            'level': level,
            'source_file': source_file,
            'message_details': message_details
        }
    
    return None

def normalize_message(message_details):
    """Normalize message details to group similar messages"""
    if not message_details:
        return ""
    
    # Remove trace information that makes messages unique
    # Remove dt.trace_id, dt.span_id, dt.trace_sampled
    message = re.sub(r'\{dt\.trace_id=[^,}]+(?:,\s*dt\.span_id=[^,}]+)?(?:,\s*dt\.trace_sampled=[^}]+)?\}', '', message_details)
    
    # Remove other unique identifiers that might be in curly braces
    message = re.sub(r'\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}', '{UUID}', message)
    message = re.sub(r'\{[a-f0-9]{8,}\}', '{HEX_ID}', message)
    
    # Replace specific UUIDs and hashes with placeholders
    message = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'UUID', message)
    message = re.sub(r'[a-f0-9]{32,}', 'HASH', message)
    
    # Replace timestamps with placeholder
    message = re.sub(r'\d{6} \d{2}\.\d{2}\.\d{2},\d{3}', 'TIMESTAMP', message)
    
    # Replace specific numbers that might vary (like line numbers, IDs, etc.)
    message = re.sub(r'\b\d{4,}\b', 'NUMBER', message)
    
    # Replace URLs with placeholder while preserving path structure
    message = re.sub(r'https?://[^\s]+', 'URL', message)
    
    # Replace IP addresses
    message = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP_ADDRESS', message)
    
    # Clean up extra whitespace
    message = ' '.join(message.split())
    
    return message.strip()

def extract_base_message(message_details):
    """Extract the base message before specific details"""
    if not message_details:
        return ""
    
    # For exception messages, get the main exception type and basic message
    if 'Exception' in message_details or 'Error' in message_details:
        # Look for patterns like "SomeException: message details"
        exception_match = re.search(r'([A-Za-z][A-Za-z0-9]*(?:Exception|Error)): ([^{]*)', message_details)
        if exception_match:
            exception_type, base_msg = exception_match.groups()
            # Clean up the base message
            base_msg = re.sub(r'[a-f0-9]{8,}', 'ID', base_msg)
            base_msg = re.sub(r'\b\d{4,}\b', 'NUM', base_msg)
            return f"{exception_type}: {base_msg.strip()}"
    
    # For other messages, try to extract the first meaningful part
    # Remove trace info first
    clean_msg = re.sub(r'\{dt\.trace_id=[^}]+\}', '', message_details)
    clean_msg = re.sub(r'\{[^}]*\}', '', clean_msg).strip()
    
    # Take the first sentence or clause
    if ':' in clean_msg:
        parts = clean_msg.split(':')
        if len(parts) > 1:
            base_part = parts[0] + ': ' + parts[1]
            # Limit length and normalize
            base_part = base_part[:200]
            base_part = re.sub(r'[a-f0-9]{8,}', 'ID', base_part)
            base_part = re.sub(r'\b\d{4,}\b', 'NUM', base_part)
            return base_part.strip()
    
    # Fallback: take first part of the message
    clean_msg = clean_msg[:150]
    clean_msg = re.sub(r'[a-f0-9]{8,}', 'ID', clean_msg)
    clean_msg = re.sub(r'\b\d{4,}\b', 'NUM', clean_msg)
    return clean_msg.strip()

def analyze_log_file(filename):
    """Analyze the log file and group messages"""
    print(f"Analyzing log file: {filename}")
    
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found!")
        return None
    
    # Counters for different categories
    level_counts = Counter()
    source_counts = Counter()
    source_file_counts = Counter()
    
    # Message grouping
    base_messages = Counter()
    
    # Raw message examples and levels for each group
    base_message_examples = defaultdict(list)
    base_message_levels = defaultdict(list)
    
    total_lines = 0
    parsed_lines = 0
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                
                parsed = parse_log_line(line)
                if parsed:
                    parsed_lines += 1
                    
                    # Count by level and source
                    level_counts[parsed['level']] += 1
                    source_counts[parsed['source']] += 1
                    source_file_counts[parsed['source_file']] += 1
                    
                    # Group messages
                    base_msg = extract_base_message(parsed['message_details'])
                    
                    if base_msg:
                        base_messages[base_msg] += 1
                        base_message_levels[base_msg].append(parsed['level'])
                        if len(base_message_examples[base_msg]) < 3:  # Keep up to 3 examples
                            base_message_examples[base_msg].append(parsed['message_details'])
                
                # Progress indicator
                if line_num % 500000 == 0:
                    print(f"  Processed {line_num:,} lines...")
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    print(f"Completed analysis: {total_lines:,} total lines, {parsed_lines:,} parsed log entries")
    
    return {
        'level_counts': level_counts,
        'source_counts': source_counts,
        'source_file_counts': source_file_counts,
        'base_messages': base_messages,
        'base_message_examples': base_message_examples,
        'base_message_levels': base_message_levels,
        'total_lines': total_lines,
        'parsed_lines': parsed_lines
    }

def save_baseline(analysis_data, filename):
    """Save analysis data as baseline for future comparisons"""
    baseline_file = "teamserver_baseline.json"
    
    # Convert Counter objects to dicts for JSON serialization
    baseline_data = {
        'filename': filename,
        'total_lines': analysis_data['total_lines'],
        'parsed_lines': analysis_data['parsed_lines'],
        'parse_rate': (analysis_data['parsed_lines']/analysis_data['total_lines']*100),
        'level_counts': dict(analysis_data['level_counts']),
        'error_rate': (analysis_data['level_counts']['ERROR'] / analysis_data['parsed_lines'] * 100) if analysis_data['parsed_lines'] > 0 else 0,
        'warn_rate': (analysis_data['level_counts']['WARN'] / analysis_data['parsed_lines'] * 100) if analysis_data['parsed_lines'] > 0 else 0,
        'top_sources': dict(analysis_data['source_counts'].most_common(10)),
        'top_source_files': dict(analysis_data['source_file_counts'].most_common(10)),
        'top_messages': dict(analysis_data['base_messages'].most_common(20)),
        'system_health': get_health_status(analysis_data)
    }
    
    with open(baseline_file, 'w') as f:
        json.dump(baseline_data, f, indent=2)
    
    print(f"\n✅ Baseline saved to {baseline_file}")
    print(f"   Use this baseline for future log comparisons with --compare flag")

def load_baseline():
    """Load baseline data for comparison"""
    baseline_file = "teamserver_baseline.json"
    
    if not os.path.exists(baseline_file):
        return None
    
    try:
        with open(baseline_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load baseline: {e}")
        return None

def get_health_status(analysis_data):
    """Determine system health status"""
    total_parsed = analysis_data['parsed_lines']
    if total_parsed == 0:
        return "UNKNOWN"
    
    error_count = analysis_data['level_counts']['ERROR']
    warn_count = analysis_data['level_counts']['WARN']
    
    if error_count / total_parsed > 0.05:  # > 5% error rate
        return "CRITICAL"
    elif error_count / total_parsed > 0.02:  # > 2% error rate
        return "DEGRADED"
    elif warn_count / total_parsed > 0.4:  # > 40% warning rate
        return "UNSTABLE"
    else:
        return "STABLE"

def compare_with_baseline(analysis_data, baseline_data):
    """Compare current analysis with baseline and return insights"""
    if not baseline_data:
        return None
    
    total_parsed = analysis_data['parsed_lines']
    current_error_rate = (analysis_data['level_counts']['ERROR'] / total_parsed * 100) if total_parsed > 0 else 0
    current_warn_rate = (analysis_data['level_counts']['WARN'] / total_parsed * 100) if total_parsed > 0 else 0
    current_parse_rate = (analysis_data['parsed_lines']/analysis_data['total_lines']*100)
    
    baseline_error_rate = baseline_data['error_rate']
    baseline_warn_rate = baseline_data['warn_rate']
    baseline_parse_rate = baseline_data['parse_rate']
    
    comparison = {
        'baseline_file': baseline_data['filename'],
        'error_rate_change': current_error_rate - baseline_error_rate,
        'warn_rate_change': current_warn_rate - baseline_warn_rate,
        'parse_rate_change': current_parse_rate - baseline_parse_rate,
        'current_health': get_health_status(analysis_data),
        'baseline_health': baseline_data['system_health'],
        'new_issues': [],
        'resolved_issues': [],
        'severity_changes': []
    }
    
    # Identify new issues (messages not in baseline)
    baseline_messages = set(baseline_data['top_messages'].keys())
    current_messages = set(msg for msg, count in analysis_data['base_messages'].most_common(50))
    
    for message in current_messages - baseline_messages:
        count = analysis_data['base_messages'][message]
        if count >= 100:  # Only flag significant new issues
            comparison['new_issues'].append((message, count))
    
    # Identify resolved issues (baseline messages not in current)
    for message in baseline_messages - current_messages:
        if baseline_data['top_messages'][message] >= 100:
            comparison['resolved_issues'].append((message, baseline_data['top_messages'][message]))
    
    # Check for severity changes in common messages
    for message in baseline_messages & current_messages:
        baseline_count = baseline_data['top_messages'][message]
        current_count = analysis_data['base_messages'][message]
        
        if baseline_count >= 10 and current_count >= 10:  # Only compare significant messages
            change_ratio = current_count / baseline_count
            if change_ratio > 3:  # 3x increase
                comparison['severity_changes'].append((message, baseline_count, current_count, 'INCREASED'))
            elif change_ratio < 0.33:  # 3x decrease
                comparison['severity_changes'].append((message, baseline_count, current_count, 'DECREASED'))
    
    return comparison

def generate_csv_reports(analysis_data, base_filename):
    """Generate CSV report from analysis data"""
    
    # Filter messages with count >= 10
    min_count = 10
    
    # CSV: Base message groups with MESSAGE_LEVEL as first column
    csv_filename = f"{base_filename}_base_messages.csv"
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['MESSAGE_LEVEL', 'Count', 'Base_Message', 'Example_Messages'])
        
        for message, count in analysis_data['base_messages'].most_common():
            if count >= min_count:
                # Determine the most common level for this message
                level_counts = Counter(analysis_data['base_message_levels'][message])
                most_common_level = level_counts.most_common(1)[0][0]
                
                examples = ' | '.join(analysis_data['base_message_examples'][message][:2])
                writer.writerow([most_common_level, count, message, examples])
    
    return [csv_filename]

def print_summary(analysis_data, comparison_data=None):
    """Print command-line summary with key insights and baseline comparison"""
    
    print("\n" + "="*80)
    print("LOG ANALYSIS SUMMARY")
    print("="*80)
    
    print(f"\nOverall Statistics:")
    print(f"  Total lines processed: {analysis_data['total_lines']:,}")
    print(f"  Parsed log entries: {analysis_data['parsed_lines']:,}")
    print(f"  Parse success rate: {(analysis_data['parsed_lines']/analysis_data['total_lines']*100):.1f}%")
    
    print(f"\nMessage Level Counts:")
    total_parsed = analysis_data['parsed_lines']
    for level, count in analysis_data['level_counts'].most_common():
        percentage = (count / total_parsed) * 100 if total_parsed > 0 else 0
        print(f"  {level:<8}: {count:>8,} ({percentage:5.1f}%)")
    
    print(f"\nTop 10 Sources:")
    print(f"  {'Count':<10} {'Source'}")
    print(f"  {'-'*10} {'-'*50}")
    for source, count in analysis_data['source_counts'].most_common(10):
        print(f"  {count:<10,} {source}")
    
    print(f"\nTop 10 Source Files:")
    print(f"  {'Count':<10} {'Source File'}")
    print(f"  {'-'*10} {'-'*50}")
    for source_file, count in analysis_data['source_file_counts'].most_common(10):
        print(f"  {count:<10,} {source_file}")
    
    print(f"\nTop 15 Base Message Groups (count >= 10):")
    print(f"  {'Level':<8} {'Count':<10} {'Base Message'}")
    print(f"  {'-'*8} {'-'*10} {'-'*60}")
    shown = 0
    for message, count in analysis_data['base_messages'].most_common():
        if count >= 10 and shown < 15:
            # Get the most common level for this message
            level_counts = Counter(analysis_data['base_message_levels'][message])
            most_common_level = level_counts.most_common(1)[0][0]
            
            # Truncate long messages for display
            display_msg = message[:60] + "..." if len(message) > 60 else message
            print(f"  {most_common_level:<8} {count:<10,} {display_msg}")
            shown += 1
    
    # Key insights and analysis results
    print(f"\n" + "="*80)
    print("KEY ANALYSIS RESULTS & INSIGHTS")
    print("="*80)
    
    # Analyze top issues
    top_issues = []
    connection_issues = 0
    broken_pipe_issues = 0
    exception_issues = 0
    
    for message, count in analysis_data['base_messages'].most_common(20):
        if count >= 100:  # Focus on high-impact issues
            message_lower = message.lower()
            if 'connection' in message_lower and 'timeout' in message_lower:
                connection_issues += count
                top_issues.append(f"Database Connection Timeouts: {count:,} occurrences")
            elif 'broken pipe' in message_lower:
                broken_pipe_issues += count
                top_issues.append(f"Broken Pipe Network Errors: {count:,} occurrences")
            elif 'exception' in message_lower and 'handler' in message_lower:
                exception_issues += count
                top_issues.append(f"Exception Handler Failures: {count:,} occurrences")
    
    print(f"\nCritical System Issues Identified:")
    for issue in top_issues[:5]:
        print(f"  • {issue}")
    
    # Error rate analysis
    error_count = analysis_data['level_counts']['ERROR']
    warn_count = analysis_data['level_counts']['WARN']
    info_count = analysis_data['level_counts']['INFO']
    
    print(f"\nSystem Health Assessment:")
    if error_count / total_parsed > 0.05:  # > 5% error rate
        health_status = "CRITICAL"
    elif error_count / total_parsed > 0.02:  # > 2% error rate
        health_status = "DEGRADED"
    elif warn_count / total_parsed > 0.4:  # > 40% warning rate
        health_status = "UNSTABLE"
    else:
        health_status = "STABLE"
    
    print(f"  Overall System Health: {health_status}")
    print(f"  Error Rate: {(error_count/total_parsed)*100:.2f}% ({error_count:,} errors)")
    print(f"  Warning Rate: {(warn_count/total_parsed)*100:.2f}% ({warn_count:,} warnings)")
    
    # Primary source analysis
    main_source = analysis_data['source_counts'].most_common(1)[0]
    agent_activity = main_source[1] if 'agent_' in main_source[0] else 0
    
    print(f"\nAgent Activity Analysis:")
    if agent_activity > 0:
        print(f"  Primary Agent: {main_source[0]}")
        print(f"  Agent Messages: {agent_activity:,} ({(agent_activity/total_parsed)*100:.1f}% of all logs)")
        
        # Check if agent is primary source of errors
        agent_error_estimate = 0
        for message, count in analysis_data['base_messages'].most_common(10):
            if 'broken pipe' in message.lower() or 'timeout' in message.lower():
                agent_error_estimate += count
        
        if agent_error_estimate > total_parsed * 0.1:  # > 10% of logs are agent-related errors
            print(f"  Agent Impact: HIGH - Significant error correlation detected")
        else:
            print(f"  Agent Impact: NORMAL - Standard operational activity")
    
    # Resource exhaustion indicators
    print(f"\nResource Exhaustion Indicators:")
    
    resource_issues = []
    for message, count in analysis_data['base_messages'].most_common(15):
        message_lower = message.lower()
        if 'pool' in message_lower and 'timeout' in message_lower:
            resource_issues.append(f"Connection Pool Exhaustion: {count:,} occurrences")
        elif 'memory' in message_lower or 'heap' in message_lower:
            resource_issues.append(f"Memory Issues: {count:,} occurrences")
        elif 'cache' in message_lower and ('evict' in message_lower or 'remove' in message_lower):
            resource_issues.append(f"Cache Pressure: {count:,} occurrences")
    
    if resource_issues:
        for issue in resource_issues:
            print(f"  • {issue}")
    else:
        print(f"  • No major resource exhaustion patterns detected")
    
    # Message grouping effectiveness
    total_unique_base = len([k for k, v in analysis_data['base_messages'].items() if v >= 10])
    total_rare_messages = len([k for k, v in analysis_data['base_messages'].items() if v < 10])
    
    print(f"\nMessage Grouping Effectiveness:")
    print(f"  Frequent message types (count >= 10): {total_unique_base:,}")
    print(f"  Rare message types (count < 10): {total_rare_messages:,}")
    print(f"  Grouping efficiency: {(total_unique_base/(total_unique_base+total_rare_messages))*100:.1f}%")
    
    # Recommendations based on analysis
    print(f"\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    
    recommendations = []
    
    if connection_issues > 1000:
        recommendations.append("URGENT: Investigate database connection pool configuration - high timeout rate")
    
    if broken_pipe_issues > 1000:
        recommendations.append("HIGH: Review network stability and client connection handling")
    
    if error_count / total_parsed > 0.05:
        recommendations.append("CRITICAL: Error rate exceeds 5% - immediate investigation required")
    
    if exception_issues > 500:
        recommendations.append("MEDIUM: Exception handler failures indicate cascading error conditions")
    
    if agent_activity > total_parsed * 0.7:
        recommendations.append("MONITOR: High agent activity - ensure agent is not overloading system")
    
    if not recommendations:
        recommendations.append("MAINTAIN: System appears stable - continue monitoring")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    
    print(f"\nFor detailed message breakdown, see the generated CSV file.")
    
    # Baseline comparison section
    if comparison_data:
        print(f"\n" + "="*80)
        print("BASELINE COMPARISON ANALYSIS")
        print("="*80)
        
        print(f"\nComparing against baseline: {comparison_data['baseline_file']}")
        print(f"Baseline System Health: {comparison_data['baseline_health']}")
        print(f"Current System Health: {comparison_data['current_health']}")
        
        # Health status change
        if comparison_data['current_health'] != comparison_data['baseline_health']:
            if comparison_data['current_health'] in ['CRITICAL', 'DEGRADED'] and comparison_data['baseline_health'] == 'STABLE':
                print(f"🚨 ALERT: System degraded from {comparison_data['baseline_health']} to {comparison_data['current_health']}")
            elif comparison_data['current_health'] == 'STABLE' and comparison_data['baseline_health'] in ['CRITICAL', 'DEGRADED']:
                print(f"✅ IMPROVEMENT: System recovered from {comparison_data['baseline_health']} to {comparison_data['current_health']}")
            else:
                print(f"📊 STATUS CHANGE: {comparison_data['baseline_health']} → {comparison_data['current_health']}")
        else:
            print(f"📊 STATUS: System health unchanged ({comparison_data['current_health']})")
        
        # Rate changes
        print(f"\nRate Changes from Baseline:")
        error_change = comparison_data['error_rate_change']
        warn_change = comparison_data['warn_rate_change']
        parse_change = comparison_data['parse_rate_change']
        
        print(f"  Error Rate: {error_change:+.2f}% change")
        print(f"  Warning Rate: {warn_change:+.2f}% change")
        print(f"  Parse Success Rate: {parse_change:+.2f}% change")
        
        # New issues
        if comparison_data['new_issues']:
            print(f"\n🔴 NEW CRITICAL ISSUES (not in baseline):")
            for message, count in comparison_data['new_issues'][:5]:
                display_msg = message[:70] + "..." if len(message) > 70 else message
                print(f"  • {count:,}x: {display_msg}")
        
        # Resolved issues
        if comparison_data['resolved_issues']:
            print(f"\n✅ RESOLVED ISSUES (present in baseline, not in current):")
            for message, baseline_count in comparison_data['resolved_issues'][:5]:
                display_msg = message[:70] + "..." if len(message) > 70 else message
                print(f"  • Was {baseline_count:,}x: {display_msg}")
        
        # Severity changes
        if comparison_data['severity_changes']:
            print(f"\n📈 SIGNIFICANT CHANGES IN EXISTING ISSUES:")
            for message, baseline_count, current_count, direction in comparison_data['severity_changes'][:5]:
                change_ratio = current_count / baseline_count
                display_msg = message[:60] + "..." if len(message) > 60 else message
                if direction == 'INCREASED':
                    print(f"  ⬆️ {display_msg}")
                    print(f"     {baseline_count:,} → {current_count:,} ({change_ratio:.1f}x increase)")
                else:
                    print(f"  ⬇️ {display_msg}")
                    print(f"     {baseline_count:,} → {current_count:,} ({1/change_ratio:.1f}x decrease)")
        
        # Recommendations based on comparison
        print(f"\n" + "="*80)
        print("BASELINE-INFORMED RECOMMENDATIONS")
        print("="*80)
        
        baseline_recommendations = []
        
        if error_change > 1.0:  # Error rate increased by more than 1%
            baseline_recommendations.append("🚨 URGENT: Error rate significantly increased - investigate immediate causes")
        
        if warn_change > 10.0:  # Warning rate increased by more than 10%
            baseline_recommendations.append("⚠️ HIGH: Warning rate spike detected - system stress indicators")
        
        if parse_change < -5.0:  # Parse rate decreased by more than 5%
            baseline_recommendations.append("📊 MEDIUM: Parse success rate declined - possible log format issues")
        
        if comparison_data['new_issues']:
            baseline_recommendations.append("🔍 HIGH: New critical issues detected - require immediate analysis")
        
        if len(comparison_data['severity_changes']) > 3:
            baseline_recommendations.append("📈 MEDIUM: Multiple issue severity changes - system behavior shift")
        
        if not baseline_recommendations:
            if comparison_data['current_health'] == 'STABLE' and comparison_data['baseline_health'] == 'STABLE':
                baseline_recommendations.append("✅ MAINTAIN: System performing within baseline parameters")
            else:
                baseline_recommendations.append("📊 MONITOR: Continue tracking against baseline")
        
        for i, rec in enumerate(baseline_recommendations, 1):
            print(f"  {i}. {rec}")
        
        print(f"\n💡 Baseline comparison provides context for identifying anomalies and trends.")
    else:
        print(f"\n💡 Tip: Run with --save-baseline to create a baseline for future comparisons.")

def main():
    """Main function"""
    # Parse command line arguments
    save_baseline_flag = False
    compare_flag = False
    log_file = None
    
    args = sys.argv[1:]
    
    if len(args) == 0:
        print("Usage: python3 teamserver_log_analyzer.py <log_file> [--save-baseline] [--compare]")
        print("Examples:")
        print("  python3 teamserver_log_analyzer.py lsit327w-contrast.log")
        print("  python3 teamserver_log_analyzer.py contrastnew.log --save-baseline")
        print("  python3 teamserver_log_analyzer.py problem.log --compare")
        sys.exit(1)
    
    # Process arguments
    for arg in args:
        if arg == '--save-baseline':
            save_baseline_flag = True
        elif arg == '--compare':
            compare_flag = True
        elif not arg.startswith('--'):
            log_file = arg
    
    if not log_file:
        print("Error: No log file specified")
        sys.exit(1)
    
    base_filename = os.path.splitext(log_file)[0]
    
    print("Starting Teamserver Log Analysis...")
    print(f"Log file: {log_file}")
    print(f"Output CSV file will be: {base_filename}_base_messages.csv")
    
    if save_baseline_flag:
        print("📊 Will save analysis as baseline for future comparisons")
    
    if compare_flag:
        print("🔍 Will compare against existing baseline")
    
    # Analyze the log file
    analysis_data = analyze_log_file(log_file)
    
    if analysis_data is None:
        print("Analysis failed!")
        sys.exit(1)
    
    # Generate CSV reports
    print(f"\nGenerating CSV report...")
    csv_files = generate_csv_reports(analysis_data, base_filename)
    
    print(f"CSV file generated:")
    for csv_file in csv_files:
        print(f"  • {csv_file}")
    
    # Load baseline for comparison if requested
    comparison_data = None
    if compare_flag:
        baseline_data = load_baseline()
        if baseline_data:
            comparison_data = compare_with_baseline(analysis_data, baseline_data)
            print(f"📊 Loaded baseline: {baseline_data['filename']}")
        else:
            print("⚠️ No baseline found. Run with --save-baseline on a clean log first.")
    
    # Print summary to console
    print_summary(analysis_data, comparison_data)
    
    # Save baseline if requested
    if save_baseline_flag:
        save_baseline(analysis_data, log_file)
    
    print(f"\nAnalysis complete! Check the CSV file for detailed message breakdown.")

if __name__ == "__main__":
    main()
