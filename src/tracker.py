import argparse
import configparser


SERVER_CONFIG = 'conf/server.conf'


def load_config_file():
    parser = configparser.ConfigParser()
    read = parser.read(SERVER_CONFIG)
    if not read:
        raise FileNotFoundError(f'[{404:5d}] CONFIG FILE NOT FOUND')
    return dict(parser)


def get_parser():
    parser = argparse.ArgumentParser(
        prog='TorTracker',
        description="Simplified tracker of torrent network",
        epilog="Spring23 - CE40443 - Assignment 2")
    parser.add_argument('IP:Port', nargs='?',
                        help='IP and Port binding of the server')
    return parser


def load_config():
    config = load_config_file()
    parser = get_parser()
    args = parser.parse_args()
    if getattr(args, 'IP:Port'):
        ip, port = getattr(args, 'IP:Port').split(':')
        config['DEFAULT']['Ip'] = ip
        config['DEFAULT']['Port'] = port
    return config


if __name__ == "__main__":
    conf = load_config()
