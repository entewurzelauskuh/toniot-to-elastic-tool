import glob
import os
import ssl
import argparse
import urllib3
import json
import logging
import urllib.request
import base64
import pandas as pd
from pathlib import Path
import locale
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.HTTPResponse)

locale.setlocale(locale.LC_ALL, "")


def remove_empties_from_dict(a_dict):
    new_dict = {}
    for k, v in a_dict.items():
        if isinstance(v, dict):
            v = remove_empties_from_dict(v)
        if v is not None:
            new_dict[k] = v
    return new_dict or None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to import TON_IoT data from CSV into elasticsearch.")
    parser.add_argument("-e --es_host", dest="es_host", type=str, default="127.0.0.1",
                        help="Address to the elasticsearch instance. Defaults to 127.0.0.1/localhost.")
    parser.add_argument("-po --es_port", dest="es_port", type=int, default=9200,
                        help="Port of the elasticsearch instance. Defaults to 9200.")
    parser.add_argument("-u --es_user", dest="es_user", type=str, required=True,
                        help="Username of elasticsearch account which has to have write access to the target index. "
                             "Required.")
    parser.add_argument("-pa --es_password", dest="es_password", type=str, required=True,
                        help="Password of elasticsearch account. Required.")
    parser.add_argument("-i --es_index", dest="es_index", type=str, required=True,
                        help="Target index to write into. Required.")
    parser.add_argument("-m --http_method", dest="http_method", type=str, default="https",
                        help="Specify http method. Default method is https.")
    parser.add_argument("-l --logging", dest="logging", default="INFO",
                        help="Set logging severity. Defaults to INFO.")
    params = parser.parse_args()

    ES_HOST = params.es_host
    ES_PORT = params.es_port
    ES_USER = params.es_user
    ES_PW = params.es_password
    INDEX_NAME = params.es_index
    HTTP_METHOD = params.http_method
    LOGGING = params.logging

    # Create logging instance with file output
    LOG_FORMATTER = logging.Formatter(fmt="%(asctime)s :: %(levelname)s :: %(message)s", datefmt="%H:%M:%S")
    LOGGER = logging.getLogger(__name__)

    FILE_HANDLER = logging.FileHandler(Path(f"./run-{datetime.now().strftime('%d-%m-%YT%H-%M-%S')}.log"))
    FILE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(FILE_HANDLER)

    CONSOLE_HANDLER = logging.StreamHandler()
    CONSOLE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(CONSOLE_HANDLER)

    if LOGGING == "DEBUG":
        LOGGER.setLevel(logging.DEBUG)
    elif LOGGING == "WARNING":
        LOGGER.setLevel(logging.WARNING)
    elif LOGGING == "ERROR":
        LOGGER.setLevel(logging.ERROR)
    elif LOGGING == "CRITICAL":
        LOGGER.setLevel(logging.CRITICAL)
    else:
        LOGGER.setLevel(logging.INFO)

    # Reading in the csv files
    folder = "./data/"
    os.chdir(Path(folder))
    li = []
    for file in glob.glob("*.csv"):
        LOGGER.info(f"Found file '{file}'! Loading ...")
        df = pd.read_csv(filepath_or_buffer=file, sep=",", header=0, engine="python")
        li.append(df)
    if not li:
        LOGGER.error("Couldn't find any csv file in the data folder, aborting.")
        exit(1)
    df = pd.concat(li, axis=0, ignore_index=True)
    li = []     # Clear memory

    LOGGER.info("Finished loading, sorting data by timestamp ...")
    df.sort_values(by=["ts"], inplace=True, ignore_index=True)

    LOGGER.info("Finished!")
    LOGGER.debug(f"\n{df.to_string(max_rows=10, max_cols=100)}")
    LOGGER.debug(f"\n{df.dtypes}")

    count = 0
    LOGGER.info(f"Ready to send {df.shape[0]} docs to cluster, Starting!")
    # Begin creating one request body per DataFrame row and send it to elastic search
    for index, row in df.iterrows():
        count = count + 1
        if count % 5000 == 0:
            LOGGER.info(f"{count / df.shape[0] * 100:.2f}% ...")

        body = {
            "@timestamp": None,
            "@version": "1",
            "ecs": {
                "version": "1.10.0"
            },
            "event": {
                "kind": "event",
                "dataset": "flow",
                "action": "network_flow",
                "category": "network_traffic",
                "start": None,
                "duration": None
            },
            "source": {
                "ip": None,
                "port": None,
                "bytes": None,
                "ip_bytes": None
            },
            "destination": {
                "ip": None,
                "port": None,
                "bytes": None,
                "ip_bytes": None
            },
            "network": {
                "protocol": None,
                "transport": None,
                "type": None,
                "bytes": row["src_bytes"] + row["dst_bytes"],
                "packets": row["src_pkts"] + row["dst_pkts"]
            },
            "http": {
                "request": {
                    "body": {
                        "bytes": None
                    },
                    "method": None,
                    "referrer": None,
                    "mime_type": None
                },
                "response": {
                    "body": {
                        "bytes": None
                    },
                    "status_code": None,
                    "mime_type": None
                },
                "version": None,
                "trans_depth": None
            },
            "user_agent": {
                "original": None
            },
            "zeek": {
                "conn_state": None,
                "missed_bytes": None
            },
            "dns": {
                "question": {
                    "class": None,
                    "name": None,
                    "type": None
                },
                "response_code": None,
                "header_flags": None,
                "rejected": None
            },
            "tls": {
                "cipher": None,
                "established": None,
                "resumed": None,
                "server": {
                  "subject": None,
                  "issuer": None
                }
            },
            "weird": {
                "name": None,
                "addl": None,
                "notice": None
            },
            "type": None,
            "label": None,
            "tags": None
        }

        header_flags = []
        dns_AA = row["dns_AA"]
        dns_RD = row["dns_RD"]
        dns_RA = row["dns_RA"]
        if dns_AA != 0 and dns_AA == "T":
            header_flags.append("AA")
        if dns_RD != 0 and dns_RD == "T":
            header_flags.append("RD")
        if dns_RA != 0 and dns_RA == "T":
            header_flags.append("RA")

        if header_flags:
            body["dns"]["header_flags"] = header_flags

        for col, v in row.items():
            if row[col] != "-":

                if col == "ts":
                    body["@timestamp"] = datetime.utcfromtimestamp(row["ts"]).strftime('%Y-%m-%dT%H:%M:%S')
                    body["event"]["start"] = datetime.utcfromtimestamp(row["ts"]).strftime("%Y-%m-%dT%H:%M:%S")

                if col == "src_ip":
                    body["source"]["ip"] = row["src_ip"]
                    body["network"]["type"] = "ipv6" if ":" in row["src_ip"] else "ipv4"

                if col == "src_port":
                    body["source"]["port"] = row["src_port"]

                if col == "dst_ip":
                    body["destination"]["ip"] = row["dst_ip"]

                if col == "dst_port":
                    body["destination"]["port"] = row["dst_port"]

                if col == "proto":
                    body["network"]["transport"] = row["proto"]

                if col == "service":
                    body["network"]["protocol"] = row["service"]

                if col == "duration":
                    body["event"]["duration"] = "{:.6f}".format(row["duration"])

                if col == "src_bytes":
                    body["source"]["bytes"] = row["src_bytes"]

                if col == "dst_bytes":
                    body["destination"]["bytes"] = row["dst_bytes"]

                if col == "conn_state":
                    body["zeek"]["conn_state"] = row["conn_state"]

                if col == "missed_bytes":
                    body["zeek"]["missed_bytes"] = row["missed_bytes"]

                if col == "src_ip_bytes":
                    body["source"]["ip_bytes"] = row["src_ip_bytes"]

                if col == "dst_ip_bytes":
                    body["destination"]["ip_bytes"] = row["dst_ip_bytes"]

                if col == "dns_query":
                    body["dns"]["question"]["name"] = row["dns_query"]

                if col == "dns_qclass":
                    body["dns"]["question"]["class"] = row["dns_qclass"]

                if col == "dns_qtype":
                    body["dns"]["question"]["type"] = row["dns_qtype"]

                if col == "dns_rcode":
                    body["dns"]["response_code"] = row["dns_rcode"]

                if col == "dns_rejected":
                    body["dns"]["rejected"] = True if row["dns_rejected"] == "T" else False

                if col == "ssl_version":
                    body["tls"]["version"] = row["ssl_version"].split("v")[1]
                    body["tls"]["version_protocol"] = row["ssl_version"].split("v")[0].lower()

                if col == "ssl_cipher":
                    body["tls"]["cipher"] = row["ssl_cipher"]

                if col == "ssl_resumed":
                    body["tls"]["resumed"] = True if row["ssl_resumed"] == "T" else False

                if col == "ssl_established":
                    body["tls"]["established"] = True if row["ssl_established"] == "T" else False

                if col == "ssl_subject":
                    body["tls"]["server"]["subject"] = row["ssl_subject"]

                if col == "ssl_issuer":
                    body["tls"]["server"]["issuer"] = row["ssl_issuer"]

                if col == "http_trans_depth":
                    body["http"]["trans_depth"] = row["http_trans_depth"]

                if col == "http_method":
                    body["http"]["request"]["method"] = row["http_method"]

                if col == "http_uri":
                    body["http"]["request"]["referrer"] = row["http_uri"]

                if col == "http_version":
                    body["http"]["version"] = row["http_version"]

                if col == "http_request_body_len":
                    body["http"]["request"]["body"]["bytes"] = row["http_request_body_len"]

                if col == "http_response_body_len":
                    body["http"]["response"]["body"]["bytes"] = row["http_response_body_len"]

                if col == "http_status_code":
                    body["http"]["response"]["status_code"] = row["http_status_code"]

                if col == "http_user_agent":
                    body["user_agent"]["original"] = row["http_user_agent"]

                if col == "http_orig_mime_types":
                    body["http"]["request"]["original"] = row["http_orig_mime_types"]

                if col == "http_resp_mime_types":
                    body["http"]["response"]["original"] = row["http_resp_mime_types"]

                if col == "weird_name":
                    body["weird"]["name"] = row["weird_name"]

                if col == "weird_addl":
                    body["weird"]["addl"] = row["weird_addl"]

                if col == "weird_notice":
                    body["weird"]["notice"] = True if row["weird_notice"] == "T" else False

                if col == "label":
                    body["label"] = row["label"]

                if col == "type":
                    body["type"] = row["type"]
                    body["tags"] = ["TON_IoT", row["type"]]

        body = remove_empties_from_dict(body)
        LOGGER.debug(f"Sending {body}")

        elastic_target = f"{HTTP_METHOD}://{ES_HOST}:{ES_PORT}/{INDEX_NAME}/_doc"
        req = urllib.request.Request(elastic_target)
        json_data = json.dumps(body)
        json_data_as_bytes = json_data.encode("utf-8")
        credentials = base64.b64encode(f"{ES_USER}:{ES_PW}".encode("utf-8")).decode("utf-8")
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", len(json_data_as_bytes))
        ssl._create_default_https_context = ssl._create_unverified_context
        response = urllib.request.urlopen(req, json_data_as_bytes)
        LOGGER.debug(f"Response {json.loads(response.read().decode('utf-8'))}")

    LOGGER.info("All done! Please check your index for completeness.")
