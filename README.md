# TeamServer Log Analyzer

A comprehensive log analysis tool for Contrast Security TeamServer logs. This tool groups and analyzes common error, warning, and info messages to help identify patterns and issues in large log files. **Now with baseline comparison support for anomaly detection and trend analysis!**

## Features

- **Message Grouping**: Intelligently groups similar log messages by extracting base patterns
- **Smart Filtering**: Only shows messages with count ≥ 10 to focus on significant patterns
- **CSV Output**: Generates structured CSV reports for further analysis
- **Command-line Summary**: Provides immediate insights and key findings
- **Issue Detection**: Automatically identifies common problems like connection timeouts, broken pipes, and system degradation
- **🆕 Baseline Comparison**: Save clean logs as baselines and compare problematic logs for anomaly detection
- **🆕 Health Monitoring**: Track system health transitions (STABLE → DEGRADED → CRITICAL)
- **🆕 Trend Analysis**: Detect new issues, resolved issues, and severity changes over time

## Installation

1. Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/teamserver-log-analyzer.git
cd teamserver-log-analyzer
```

2. The script requires Python 3.6+ with standard libraries only (no additional dependencies needed)

## Usage

### Basic Analysis
```bash
python3 teamserver_log_analyzer.py <log_file>
```

### Baseline Functionality (NEW!)

#### Create a Baseline from Clean Logs
```bash
python3 teamserver_log_analyzer.py clean_log.log --save-baseline
```

#### Compare Problematic Logs Against Baseline
```bash
python3 teamserver_log_analyzer.py problem_log.log --compare
```

### Example Workflow
```bash
# Step 1: Create baseline from a clean/healthy log
python3 teamserver_log_analyzer.py contrastnew.log --save-baseline

# Step 2: Analyze problematic logs with baseline comparison
python3 teamserver_log_analyzer.py lsit327w-contrast.log --compare

# Step 3: Regular analysis without baseline
python3 teamserver_log_analyzer.py some_other_log.log
```

## Log Format Support

The analyzer supports Contrast Security TeamServer log format:
```
{DATE} {TIME} {Hash} {source} {} {MESSAGE_LEVEL} (SOURCEFILE:LINE#) {message details}
```

Example:
```
260625 07.44.13,549 {5b3866838d2b} {agent_b13e3326-fe69-4358-83b0-e31c2d1a144b@Pnc} {} WARN (AbstractHandlerExceptionResolver.java:199) {dt.trace_id=5aeddd051a13aad50e0443b107b740a6} Resolved [org.springframework.web.context.request.async.AsyncRequestNotUsableException: ServletOutputStream failed to flush: java.io.IOException: Broken pipe]
```

## Output

### CSV File
- **File**: `{logfile}_base_messages.csv`
- **Columns**: MESSAGE_LEVEL, Count, Base_Message, Example_Messages
- **Content**: Grouped messages with count ≥ 10, including examples of the original messages

### Command-line Summary
- Overall statistics (total lines, parse rate, etc.)
- Message level breakdown (ERROR, WARN, INFO percentages)
- Top 10 sources generating messages
- Top 10 source files with most activity
- Top 10 most common message groups
- **Key Insights**: Automated analysis of critical issues found
- **System Health Assessment**: Analysis of error patterns and degradation

## Baseline Comparison Analysis

### What is Baseline Analysis?
Baseline analysis allows you to:
- **Save a clean log** as a reference point when your system is healthy
- **Compare problematic logs** against this baseline to identify what changed
- **Detect anomalies** by highlighting new issues, resolved issues, and severity changes
- **Track system health** transitions over time

### How It Works
1. **Create Baseline**: Run analysis on a clean log with `--save-baseline`
2. **Compare**: Analyze new logs with `--compare` to see deviations from baseline
3. **Get Insights**: Receive contextual analysis showing what's new, what's resolved, and what's gotten worse

### Baseline Comparison Output
When using `--compare`, you'll get additional analysis sections:

```
================================================================================
BASELINE COMPARISON ANALYSIS
================================================================================

Comparing against baseline: contrastnew.log
Baseline System Health: STABLE
Current System Health: DEGRADED
🚨 ALERT: System degraded from STABLE to DEGRADED

Rate Changes from Baseline:
  Error Rate: +2.74% change
  Warning Rate: +24.65% change
  Parse Success Rate: -86.11% change

🔴 NEW CRITICAL ISSUES (not in baseline):
  • 2,978x: Application exception overridden by commit exception
  • 1,408x: [TASK] 0 successful keys for DOTNET

📈 SIGNIFICANT CHANGES IN EXISTING ISSUES:
  ⬆️ [PREFLIGHT] duplicate instance found: NUM for rule
     854 → 10,037 (11.8x increase)

================================================================================
BASELINE-INFORMED RECOMMENDATIONS
================================================================================
  1. 🚨 URGENT: Error rate significantly increased - investigate immediate causes
  2. ⚠️ HIGH: Warning rate spike detected - system stress indicators
  3. 🔍 HIGH: New critical issues detected - require immediate analysis
```

## Key Insights Provided

The analyzer automatically identifies and reports:

1. **Database Connection Issues**
   - Connection pool exhaustion
   - Timeout patterns
   - Resource contention

2. **Network Connectivity Problems**
   - Broken pipe errors
   - Client disconnections
   - API endpoint failures

3. **System Degradation Patterns**
   - Error rate trends
   - Performance bottlenecks
   - Recovery patterns

4. **Application Health Metrics**
   - Spring Boot error cascades
   - Transaction failures
   - Exception handling issues

## Example Output

```
================================================================================
TEAMSERVER LOG ANALYSIS SUMMARY
================================================================================

Overall Statistics:
  Total lines processed: 4,226,458
  Parsed log entries: 441,900
  Parse success rate: 10.5%

Message Level Counts:
  INFO    :  271,439 ( 61.4%)
  WARN    :  158,358 ( 35.8%)
  ERROR   :   12,103 (  2.7%)

Top 10 Base Message Groups (count >= 10):
  Count      Base Message
  ---------- ------------------------------------------------------------
  20,952     Can't acquire connection due to timeout at the connection po...
  10,037     [PREFLIGHT] duplicate instance found:  NUM for rule
  6,824      Failure in @ExceptionHandler contrast.teamserver.rest.ng.age...

KEY INSIGHTS FROM LOG ANALYSIS:
🔥 CRITICAL ISSUES DETECTED:
  • Database Connection Pool Exhaustion: 20,952 timeout errors
  • Network Connectivity Problems: 6,365+ broken pipe errors
  • System Error Cascade: 6,824 exception handler failures

📊 SYSTEM HEALTH ASSESSMENT:
  • Error Rate: 2.7% (12,103 errors out of 441,900 messages)
  • Primary Issue: Database connection timeouts (47.3% of all errors)
  • Secondary Issue: Network connectivity failures (14.4% of all errors)
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v2.0.0 (Current)
- **NEW**: Baseline comparison functionality for anomaly detection
- **NEW**: Save clean logs as baselines with `--save-baseline`
- **NEW**: Compare problematic logs against baseline with `--compare`
- **NEW**: System health tracking (STABLE, UNSTABLE, DEGRADED, CRITICAL)
- **NEW**: Identify new issues, resolved issues, and severity changes
- **NEW**: Baseline-informed recommendations for targeted troubleshooting
- **ENHANCED**: More detailed system health assessment
- **ENHANCED**: Better trend analysis and rate change detection

### v1.0.0
- Initial release
- Message grouping and analysis
- CSV output generation
- Command-line summary with key insights
- Support for Contrast Security TeamServer log format
