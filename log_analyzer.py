# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import argparse
import collections
import datetime
import gzip
import json
import logging
import os
import re
from dataclasses import dataclass, asdict
from functools import wraps
from statistics import mean, median

LOG_PATTERN = (
    r'(\S+) (\S+)  (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" '
    r'(\S+) (\S+) "(\S+)" "(.+)" "(\S+)" "(\S+)" "(\S+)" (\S+)'
)
LOG_RE = re.compile(LOG_PATTERN)


@dataclass
class Config:
    """
    Log miner util config
    """

    report_size: int = 1000
    report_dir: str = "./reports"
    logs_dir: str = "./logs"
    err_to_file: str = ""
    err_lines_threshold: float = 0.1

    @classmethod
    def from_file(cls, config_path):
        file_config = asdict(Config())

        try:
            with open(config_path) as f:
                file_config.update(json.load(f))
        except IOError:
            print("Proceed with a default config...")

        file_config["report_dir"] = os.path.abspath(file_config["report_dir"])
        file_config["logs_dir"] = os.path.abspath(file_config["logs_dir"])

        return cls(**file_config)


def count_items(gen):
    """Decorator that counts items in a generator"""

    @wraps(gen)
    def wrapper(*args, **kwargs):
        for item in gen(*args, **kwargs):
            wrapper.calls += 1
            yield item

    wrapper.calls = 0
    return wrapper


def gen_find(file_pattern, top_dir):
    reg_expr = re.compile(file_pattern)
    for path, dir_list, file_list in os.walk(top_dir):
        for name in filter(reg_expr.search, file_list):
            yield os.path.join(path, name)


def gen_fn_date(files, date_fmt):
    for fn in files:
        datestr = fn.rsplit("-", 1)[1].rsplit(".", 1)[0]
        yield datetime.datetime.strptime(datestr, date_fmt).date(), fn


def file_open(filename):
    return gzip.open(filename) if filename.endswith(".gz") else open(filename)


@count_items
def gen_lines(log_file):
    for item in log_file:
        yield item


def field_map(dict_seq, name, func):
    for d in dict_seq:
        d[name] = func(d[name])
        yield d


@count_items
def nginx_log(log_lines):
    groups = (LOG_RE.match(line) for line in log_lines)
    values = (g.groups() for g in groups if g)
    headers = (
        "remote_addr",
        "remote_user",
        "http_x_real_ip",
        "time_local",
        "request_verb",
        "url",
        "request_prot",
        "status",
        "body_bytes_sent",
        "$http_referer",
        "http_user_agent",
        "http_x_forwarded_for",
        "http_X_REQUEST_ID",
        "http_X_RB_USER",
        "request_time",
    )
    log = (dict(zip(headers, t)) for t in values)
    log = field_map(log, "request_time", float)
    return log


def url_accumulator(logs):
    url_time = collections.defaultdict(list)
    for item in logs:
        url = item["url"]
        request_time = item["request_time"]
        url_time[url] += [request_time]

    return url_time


def url_count_requests(url_time):
    count = 0
    time = 0
    for item in url_time.values():
        count += len(item)
        time += sum(item)

    return count * 1.0, time


def url_statistics(url_time):
    all_count, all_time = url_count_requests(url_time)
    url_stats = []

    for url in url_time:
        item_stats = {}
        url_reqs = url_time[url]

        item_stats["count"] = len(url_reqs)
        item_stats["count_perc"] = round(item_stats["count"] / all_count, 4)
        item_stats["time_sum"] = round(sum(url_reqs), 4)
        item_stats["time_perc"] = round(item_stats["time_sum"] / all_time, 4)
        item_stats["time_avg"] = round(mean(url_reqs), 4)
        item_stats["time_max"] = max(url_reqs)
        item_stats["time_med"] = median(url_reqs)
        item_stats["url"] = url

        url_stats.append(item_stats)

    return url_stats


def report_template():
    with open("report.html") as template:
        return template.read()


def report_write(url_stats, report_file, report_size):
    report_data = url_stats
    if len(url_stats) > report_size:
        report_data = sorted(url_stats, reverse=True, key=lambda it: it["time_sum"])[
                      :report_size
                      ]

    report_data_json = json.dumps(report_data)
    template = report_template()

    with open("tmpreport.html", mode="w") as tmp_file:
        report_content = template.replace("$table_json", report_data_json)
        tmp_file.write(report_content)

    # report directory may not exist
    report_dir = os.path.dirname(report_file)
    os.makedirs(report_dir, exist_ok=True)
    os.rename("tmpreport.html", report_file)


def main():
    parser = argparse.ArgumentParser(description="UI logs parser util")
    parser.add_argument(
        "--config",
        dest="file",
        default="",
        required=False,
        help="Path to config file",
    )
    config = Config.from_file(parser.parse_args().file)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
        filename=config.err_to_file,
    )

    try:
        files = gen_find("nginx-access-ui.log-\d{8}($|.gz$)", config.logs_dir)

        try:
            max_date, log_file_name = max(
                gen_fn_date(files, "%Y%m%d"), key=lambda x: x[0]
            )
        except ValueError:
            logging.info(
                "Cannot find most recent log file: either there's no file or "
                "a date format in file names has changes"
            )
            return

        report_file = os.path.join(
            config.report_dir, "report-{0:%Y.%m.%d}.html".format(max_date)
        )

        if os.path.exists(report_file):
            logging.info(
                f"The latest log {log_file_name} has been already "
                f"processed with a report saved at {report_file}",
            )
            return
        else:
            with file_open(log_file_name) as log_file:
                raw_lines = gen_lines(log_file)
                logs = nginx_log(raw_lines)
                url_time = url_accumulator(logs)

                # check output lines number after parsing
                logs_out_perc = nginx_log.calls * 1.0 / gen_lines.calls
                logging.info(
                    f"Share of lines recognized as valid logs: {logs_out_perc}"
                )
                if (1.0 - logs_out_perc) > config.err_lines_threshold:
                    logging.error(
                        "Amount of lines with wrong formatting exceeded "
                        f"the relative threshold of {config.err_lines_threshold}",
                    )
                    return

            url_stats = url_statistics(url_time)
            report_write(url_stats, report_file, config.report_size)

    except Exception as err:
        logging.exception(err)


if __name__ == "__main__":
    main()
