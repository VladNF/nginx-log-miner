import io
import pytest
import log_analyzer as l


@pytest.fixture
def log():
    return (
        '1 -  - [29/Jun/2017:03:50:22 +0300] "GET /url1 HTTP/1.1" 200 927 "-" "bs1" "-" "1" "d" 0.3\n'
        '2 b  - [29/Jun/2017:03:50:22 +0300] "GET /url2 HTTP/1.1" 200 12 "-" "bs1" "-" "1" "-" 0.1'
    )


@pytest.fixture
def file(log):
    return io.StringIO(log)


def test_gen_lines(file):
    assert len(list(l.gen_lines(file))) == 2


def test_nginx_log(file):
    logs = l.nginx_log(file)
    item = next(logs)
    assert item["url"] == "/url1"
    item = next(logs)
    assert item["url"] == "/url2"


def test_url_accumulator(file):
    logs = l.nginx_log(file)
    url_acc = l.url_accumulator(logs)
    assert url_acc["/url1"][0] == 0.3
    assert url_acc["/url2"][0] == 0.1
