#!/usr/bin/env python3

import argparse
import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import tarfile
import webbrowser
from abc import ABC
from functools import cached_property
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Optional

import boto3
import pyperclip
import requests
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from pydantic import FileUrl, HttpUrl

# from tqdm import tqdm

LOGGER = logging.getLogger(__name__)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")


class BaseAwsWrapper(ABC):
    def __init__(self, profile_name: Optional[str] = None):
        self._profile_name = profile_name

        if not self.is_logged_in():
            print("Please log in to AWS cli")
            sys.exit(1)

    def cli_execute(self, command):
        with Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE) as process:
            output, err = process.communicate(
                b"input data that is passed to subprocess' stdin"
            )
            if err:
                print(err.decode("utf-8"))

        return output.decode("utf-8")

    def aws_cli_execute(self, command):
        command.insert(0, "aws")
        return self.cli_execute(command)

    def _prompt(self, name: str, available: list[str]) -> str:
        """Generic reusable user input prompt."""
        if len(available) == 1:
            return available[0]

        completer = WordCompleter(available)
        return prompt(f"{name} was not passed, choose a {name}: ", completer=completer)

    @cached_property
    def profile_name(self):
        if not self._profile_name:
            self._profile_name = self.profile_prompt()
        return self._profile_name

    @cached_property
    def available_profiles(self) -> list[str]:
        return self.aws_cli_execute(["configure", "list-profiles"]).split("\n")

    def profile_prompt(self) -> str:
        return self._prompt("profile", self.available_profiles)

    @cached_property
    def session(self):
        return boto3.Session(profile_name=self.profile_name)

    @cached_property
    def identity(self) -> dict:
        if identity := self.aws_cli_execute(["sts", "get-caller-identity"]):
            return json.loads(identity)
        return {}

    @cached_property
    def config_identity(self):
        return self.aws_cli_execute(["configure", "list"]).split("\n")

    def is_logged_in(self) -> bool:
        """
        Check to see if the user is logged in to AWS
        """
        return bool(self.identity)

    def get_account_id(self) -> bool:
        return self.identity.get("Account")

    @cached_property
    def region(self) -> str:
        ident = self.config_identity
        region_line = [x for x in ident if "region" in x][0]
        return region_line.split()[1]


class AwsAcm(BaseAwsWrapper):
    def __init__(
        self,
        profile_name: Optional[str] = None,
        certificate_domain: Optional[str] = None,
    ):
        super().__init__(profile_name)

        self._certificate_domain = certificate_domain

    @cached_property
    def acm(self):
        return self.session.client("acm", region_name=self.region)

    @cached_property
    def available_certificate_arns(self) -> dict[str:str]:
        y = self.acm.list_certificates()
        return {
            x["DomainName"]: x["CertificateArn"] for x in y["CertificateSummaryList"]
        }

    def certificate_prompt(self):
        return self._prompt("certificate", self.available_certificate_arns.keys())

    @cached_property
    def certificate_domain(self):
        if not self._certificate_domain:
            self._certificate_domain = self.certificate_prompt()
        return self._certificate_domain

    def get_certificate_arn(self, certificate_domain):
        return self.available_certificate_arns.get(certificate_domain)

    def get_certificate_id(self, certificate_domain):
        return self.get_certificate_arn(certificate_domain).split("/")[-1]

    @cached_property
    def certificate_arn(self):
        return self.get_certificate_arn(self.certificate_domain)

    @cached_property
    def certificate_id(self):
        return self.get_certificate_id(self.certificate_domain)


@contextlib.contextmanager
def ignore_user_entered_signals():
    """
    Ignores user entered signals to avoid process getting killed.
    """
    signal_list = [signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP]
    actual_signals = []
    for user_signal in signal_list:
        actual_signals.append(signal.signal(user_signal, signal.SIG_IGN))
    try:
        yield
    finally:
        for sig, user_signal in enumerate(signal_list):
            signal.signal(user_signal, actual_signals[sig])


class CommandLine:
    def _execute(self, command):
        with Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE) as process:
            output, err = process.communicate(
                b"input data that is passed to subprocess' stdin"
            )
            if err:
                print(err.decode("utf-8"))

        return output

    def cli_execute(self, command):
        return self._execute(command).decode("utf-8")

    def aws_cli_execute(self, profile_name, service, command):
        command.insert(0, service)
        command.insert(0, f"--profile={profile_name}")
        command.insert(0, "aws")
        return json.loads(self.cli_execute(command))


class EasyRSA(CommandLine):
    TMP_DIR = "/tmp/easy_rsa_vpn"
    VERSION = "3.0.7"
    GITHUB_ACCOUNT = "ahonnecke"  # TODO: change to non-bus-factor location (pasa)

    @property
    def tags_url(self) -> HttpUrl:  # test this
        return f"https://github.com/{self.GITHUB_ACCOUNT}/easy-rsa/archive/refs/tags"

    @property
    def tarfile(self) -> str:
        # https://github.com/ahonnecke/easy-rsa/archive/refs/tags/v3.0.7.tar.gz
        return f"v{self.VERSION}.tar.gz"

    @property
    def tarball_url(self) -> HttpUrl:  # test this
        return f"{self.tags_url}/v{self.VERSION}/{self.tarfile}"

    @property
    def local_tarball(self) -> FileUrl:
        return f"{self.TMP_DIR}/{self.tarfile}"

    @property
    def destination(self) -> FileUrl:
        return f"{self.TMP_DIR}/easy-rsa-{self.VERSION}/easyrsa3/"

    @property
    def executable(self) -> FileUrl:
        return f"{self.destination}/easyrsa"

    @property
    def pki(self) -> FileUrl:
        return f"{self.destination}/pki"

    def fetch(self):
        if not os.path.isdir(self.TMP_DIR):
            os.makedirs(self.TMP_DIR)

        print(f"Fetching {self.tarball_url} to {self.local_tarball}")
        data = requests.get(self.tarball_url)

        # Save file data to local copy
        with open(self.local_tarball, "wb") as file:
            file.write(data.content)

        return True

    def extract(self):
        if not os.path.isdir(self.TMP_DIR):
            raise Exception("No tmp dir")

        file_obj = tarfile.open(self.local_tarball, "r")

        print(f"extracting {self.local_tarball} to {self.TMP_DIR}")

        # extract all files
        file_obj.extractall(self.TMP_DIR)

        file_obj.close()

    def execute(self, command):
        command.insert(0, self.executable)
        return self.cli_execute(command)

    def run(self, command):
        command.insert(0, self.executable)
        return subprocess.run(command)

    def init(self):
        if not os.path.isfile(self.local_tarball):
            self.fetch()

        if not os.path.isfile(self.executable):
            self.extract()

        print("init PKI")
        self.execute(["init-pki"])

        print("build ca")
        with ignore_user_entered_signals():
            self.run(["build-ca", "nopass"])

        return True

    def generate_server(self):
        with ignore_user_entered_signals():
            self.run(["build-server-full", "server", "nopass", "nopass"])

    def generate_clients(self, clients):
        with ignore_user_entered_signals():
            for client in clients:
                self.run(["build-client-full", client, "nopass", "nopass"])


def parse_args():
    """
    Extract the CLI arguments from argparse
    """
    _parser = argparse.ArgumentParser(description="Exec into a fargate container")

    _parser.add_argument("-p", "--profile", help="AWS profile name", required=False)
    _parser.add_argument("-c", "--domain", help="Certificate domain", required=False)

    return _parser.parse_args()


def load_file(name, file_path):
    BEGIN = "-----BEGIN"

    with open(file_path, "r") as f:
        body = f.read()
        certificate = BEGIN + body.split(BEGIN)[-1]
        pyperclip.copy(certificate.strip("\n"))
        print(f"Loaded {name} into clipboard")

    while not query_yes_no(f"Finished with {name}"):
        continue


def process(region, name, cert_id, body_path, private_key_path, chain_path):

    print(f"=========== {name} ============")
    print(f"Navigate to {name} certificate reimport form")

    aws_root = f"https://{region}.console.aws.amazon.com"
    reimport_url = f"{aws_root}/acm/home#/certificates/{cert_id}/reimport"

    if query_yes_no(f"Open browser at {reimport_url}"):
        webbrowser.open(reimport_url)
    else:
        print(reimport_url)

    print(f"=========== {name} certificate files ============")
    print(f"Body: {body_path}")
    print(f"Private Key: {private_key_path}")
    print(f"Chain: {chain_path}")

    load_file(f"{name} body", body_path)
    load_file(f"{name} private key", private_key_path)
    load_file(f"{name} chain", chain_path)

    # with open(private_key_path, "r") as f:
    #     pyperclip.copy(f.read().strip("\n"))
    #     print(f"Loaded {name} certificate private key into clipboard")

    # while not query_yes_no(f"Finished with {name} private key"):
    #     continue

    # with open(chain_path, "r") as f:
    #     pyperclip.copy(f.read().strip("\n"))
    #     print(f"Loaded {name} certificate chain into clipboard")

    # while not query_yes_no(f"finished with {name} certificate chain"):
    #     continue


def main():
    args = parse_args()
    easy_rsa = EasyRSA()

    easy_rsa.init()
    easy_rsa.generate_server()

    curr_dir = Path(__file__).parent.parent
    acm = AwsAcm(
        profile_name=args.profile,
        certificate_domain=args.domain,
    )

    easy_rsa.generate_clients(acm.certificate_domain)
    for client in ["server", acm.certificate_domain]:
        process(
            acm.region,
            client,
            acm.get_certificate_id(client),
            f"{curr_dir}/pki/issued/{client}.crt",
            f"{curr_dir}/pki/private/{client}.key",
            f"{curr_dir}/pki/ca.crt",
        )

    # webbrowser.open(cert_url)

    # client_vpn_endpoints = easy_rsa.aws_cli_execute(
    #     acm.profile_name, "ec2", ["describe-client-vpn-endpoints"]
    # )["ClientVpnEndpoints"]

    # endpoints = {}
    # for endpoint in client_vpn_endpoints:
    #     endpoint["Name"] = [
    #         tag["Value"] for tag in endpoint["Tags"] if tag.get("Key") == "Name"
    #     ].pop()
    #     endpoints[endpoint["Name"]] = endpoint

    # endpoint_name = acm._prompt("endpoint name", endpoints.keys())
    # endpoint = endpoints[endpoint_name]

    # endpoint_url = f"{aws_root}/vpc/home#ClientVPNEndpointDetails:clientVpnEndpointId={endpoint['ClientVpnEndpointId']}"
    # webbrowser.open(endpoint_url)

    # print("Fin.")


if __name__ == "__main__":
    main()
