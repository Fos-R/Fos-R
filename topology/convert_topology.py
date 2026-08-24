import argparse
from dataclasses import dataclass, field
import json
import yaml

from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class FeditngenNode:
    name: str
    ipAddr: str
    ipAddrInterco: str | None = None
    os: str | None = None
    services: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FeditngenRouterNode:
    ipAddr: str
    name: str


@dataclass(frozen=True)
class FeditngenSubnet:
    name: str
    networkAddress: str
    networkMask: int
    nodeList: list[FeditngenNode]
    osPresent: dict[str, bool]
    routerNode: FeditngenRouterNode
    servicePresent: dict[str, bool]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]):
        return cls(
            name=data["name"],
            networkAddress=data["networkAddress"],
            networkMask=data["networkMask"],
            nodeList=[FeditngenNode(**node) for node in data["nodeList"]],
            osPresent=data["osPresent"],
            routerNode=FeditngenRouterNode(**data["routerNode"]),
            servicePresent=data["servicePresent"],
        )


def convertFdtgService(service: str) -> list[str]:
    """
    Convert a feditngen service name to the Fos-R equivalent
    :param str service: The name of the service to convert
    :returns: A list of str of Fosr services
    """
    match service:
        case "web_server":
            return ["https"]
        case "ftp_server":
            return ["ftp"]
        case "mail_server":
            return ["imap", "smtp"]
        case "cloud_storage":
            return ["https"]
        case "log_server":
            return ["https"]
        case "dbms_server":
            return ["https"]
        case "cms_server":
            return ["https"]
        case "proxy_server":
            return ["https"]
        case "ldap_server":
            return ["ldap"]
        case "dns_server":
            return ["dns"]
        case "ssh_server":
            return ["ssh"]
        case _:
            raise ValueError(f"Unknown service: {service}")


def convert(feditngen_out: list[FeditngenSubnet], name: str) -> dict[Any]:
    """
    Convert a Feditngen output format to the Fos-R input format
    :param list[FeditngenSubnet] feditngen_out: A list of Feditngen format subnets
    :returns: A dictionnary of the same subnets in Fos-R format
    """
    subnets = []
    for subnet in feditngen_out:
        hosts = []
        for node in subnet.nodeList:
            hostname = node.name
            os = node.os
            if os:
                os = os.capitalize()
            node_type = None

            services = []
            for s in node.services:
                services.extend(convertFdtgService(s))
            interface = {"ip_addr": node.ipAddr}
            if services:
                interface["services"] = services
            host = {
                "hostname": hostname,
                "os": os,
                "type": node_type,
                "interfaces": [interface],
            }
            hosts.append({k: v for k, v in host.items() if v})

        subnets.append(
            {
                "subnet": subnet.networkAddress,
                "mask": subnet.networkMask,
                "name": subnet.name,
                "hosts": hosts,
            }
        )

    return {
        "metadata": {
            "title": name,
            "desc": "Generated with Feditngen",
            "author": "Fos-R",
            "version": "1.0.0",
            "format": 1,
        },
        "networks": subnets,
    }


def main():
    parser = argparse.ArgumentParser("FedITN_Gen’s topology to Fos-R’s network description")
    parser.add_argument(
        "-i",
        "--input",
        help="Path to the directory containing the FedITN_Gen .json output files.",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the directory for output Fos-R .yml files.",
        required=True,
    )

    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    for p in input_dir.iterdir():
        file_name = p.stem
        with p.open("r") as f:
            json_content = json.load(f)
            subnet_list = [FeditngenSubnet.from_dict(x) for x in json_content]
            converted_content = convert(subnet_list, file_name)
            yaml_content = yaml.dump(converted_content, sort_keys=False)

            with open(output_dir / f"{file_name}.yml", "w") as output:
                output.write(yaml_content)


if __name__ == "__main__":
    main()
