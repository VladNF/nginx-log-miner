! NB: this project was recently migrated from Python 2.7, so forgive me no type annotations

The script analyzes nginx log file and generates the report of most time-consuming requests.

Log files are expected to have the following format:
 
* it corresponds to the regular expression '(\S+) (\S+)  (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\S+) (\S+) "(\S+)" "(.+)" "(\S+)" "(\S+)" "(\S+)" (\S+)'
* and has the following columns 'remote_addr', 'remote_user', 'http_x_real_ip', 'time_local', 'request_verb', 'url', 'request_prot',
                'status', 'body_bytes_sent', '$http_referer', 'http_user_agent', 'http_x_forwarded_for',
                'http_X_REQUEST_ID', 'http_X_RB_USER', 'request_time'
                
To launch the script run log_analyzer.py. It support one command line argument --config to point to a config file.
A config file should be formatted as below, its values have a priority over default config.

```
{
    "report_size": 1000,
    "report_dir": "../../data/reports",
    "logs_dir": "../../data/log",
    "err_to_file": "log_analyzer.log",
}
```

To run tests just type pytest.
