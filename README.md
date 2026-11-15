SecuPredict Monitor

Prototype of the host monitoring and alerting layer of SecuPredict, a cybersecurity service for small and medium businesses in Kazakhstan. Built for the Technological Entrepreneurship course at Astana IT University (group CS-2431). Current version: 0.2.0.

What this is

A single Python file that:

collects real metrics from the computer it runs on (CPU, memory, disk usage, network and disk throughput);
adds a simulated fleet of devices for one of two demo profiles, a medical clinic or an online shop;
raises alerts from threshold rules and from a scripted demo scenario;
shows hosts, charts and alerts in a local web dashboard that refreshes every 2 seconds;
forwards alerts of medium severity and above to a Telegram bot.
What this is not

Please read this before evaluating the prototype.

There is no machine learning in this code. Detection is limited to threshold rules and a timed scenario. The predictive model described in the project documents is planned and not implemented.
Only the machine running the script is monitored with real data. All other devices on the dashboard are simulated.
The demo scenario alerts (login from an unfamiliar address, ransomware-like activity, password guessing, full backup storage, missing updates) are produced by a timer. Phrases in them such as "isolated the computer" or "blocked the address" describe simulated actions. The program does not isolate hosts, stop processes or block IP addresses. The "isolated" state on the dashboard only changes how a simulated host is displayed.
There is no agent for other machines, no multi-tenant backend, no user accounts and no billing.
Requirements
Python 3.8 or newer
Standard library only
psutil is optional and gives more accurate metrics on Windows: pip install psutil

Without psutil the program reads /proc on Linux. On other systems without psutil, some metrics are reported as zero.

Quick start
python secupredict_monitor.py

The dashboard opens at http://127.0.0.1:8080. The first alert from the demo scenario appears after about 10 seconds and the critical one after about 25 seconds.

Command line options
Option	Description
--profile {clinic,online_shop}	Demo fleet to simulate. Default: clinic.
--host ADDRESS	Address the dashboard listens on. Default: 127.0.0.1.
--port N	Dashboard port. Default: 8080.
--no-scenario	Disable the demo scenario and use only real metrics and threshold rules.
--loop	Repeat the demo scenario every 5 minutes.
--tg-min {low,medium,high,critical}	Lowest severity sent to Telegram. Default: medium.
--no-telegram	Do not start the Telegram bot.
--no-browser	Do not open the browser automatically.
--data-dir PATH	Directory for runtime files. Default: current directory.
-v, --verbose	Print informational log messages.
Telegram alerts
Create a bot with BotFather and copy its token.
Pass the token through an environment variable. Do not write it into the source file. Linux or macOS:
export TG_BOT_TOKEN="your-token"

Windows PowerShell:

$env:TG_BOT_TOKEN="your-token"
Start the program and send /start to your bot.

Bot commands:

Command	Action
/start	Subscribe the chat to alerts.
/stop	Unsubscribe the chat.
/status	Send a summary of host states and the number of open alerts.

The bot sends alerts only. Metrics stay on the dashboard. Alerts raised before anyone has subscribed are kept in a buffer of 10 messages and delivered after the first /start. If TG_CHAT_ID is set, that chat is added as a permanent subscriber.

If no token is set, the program works normally and alerts appear only on the dashboard.

Alerts
Threshold rules

Rules are checked every sampling interval (2 seconds) for every host.

Metric	Threshold	Severity
CPU	above 90%	medium
Memory	above 92%	medium
Disk usage	above 90%	medium

A threshold must be exceeded continuously for 20 seconds before an alert is raised. After an alert, the same rule on the same host stays silent for 10 minutes.

Demo scenario
Time from start	Event	Severity
0:10	Login from an unfamiliar address	medium
0:21 to 0:25	Ransomware-like activity on one workstation	critical
0:40 to 0:45	Password guessing against the main server	high
1:05 to 1:10	Backup storage nearly full	medium
1:35	Updates not installed for a long time	low

Every alert contains what happened, what was done, and a numbered list of steps for the business owner, written in plain Russian. On the dashboard each alert is labeled either as a real-metrics alert or as a demo scenario alert, and can be acknowledged.

Dashboard
Overall status band that follows the most severe open alert.
Table of hosts with status, CPU, memory, disk and network values.
Chart of CPU and memory for the selected host over the last 5 minutes.
Alert list with details and an acknowledge button.
Telegram connection state and subscriber count.

The dashboard is one embedded HTML page with no external libraries and works without internet access. The interface language is Russian.

HTTP interface
Method and path	Description
GET /	Dashboard page.
GET /api/state	Full state as JSON: hosts, history, alerts, scenario and Telegram status.
POST /api/alerts/<id>/ack	Mark an alert as acknowledged.
Runtime files

Created in the data directory:

alerts.jsonl: every raised alert, one JSON object per line.
tg_subscribers.json: chat identifiers subscribed through /start.
Structure

The program starts several threads:

sampler: every 2 seconds reads real metrics for the local host, advances the simulation for demo hosts and evaluates threshold rules;
scenario: runs the timed demo events;
Telegram polling: receives bot commands with long polling and retries with increasing delay on network errors;
Telegram sending: takes alerts from a queue and sends them to subscribers;
HTTP server: serves the dashboard and the JSON interface.

Alerts are kept in memory (last 500), appended to alerts.jsonl and passed to registered listeners, of which the Telegram bot is one.

Security notes
The dashboard has no authentication. By default it listens on 127.0.0.1 only. Using --host 0.0.0.0 exposes the state and the acknowledge endpoint to everyone on the network.
Keep the bot token out of the repository. If a token has ever been committed or shared, revoke it in BotFather and issue a new one.
Runtime files can contain chat identifiers and should not be committed. Suggested .gitignore:
alerts.jsonl
tg_subscribers.json
.env
__pycache__/
Planned, not implemented
Endpoint agents and log collection from multiple client devices.
Real network and process isolation and IP blocking.
Industry-specific predictive models.
Monthly report and compliance checklist.
Analyst review workflow and production incident handling.
Multi-tenant cloud service, onboarding and billing.
Team

Turzhan Darkhan, Nurassyl Alibekuly, Taigaraev Erassyl. Instructor: Assel Nurguzhina, Astana IT University.

License: not specified.
