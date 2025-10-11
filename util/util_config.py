import configparser
import errors as e

def confirm_network_mask(network_address_with_mask):
    subnetmask = int(network_address_with_mask[-2:])
    if subnetmask < 16:
        raise e.networkToSmallError

def assable_java_path_for_jpype() -> str:
    config = configparser.ConfigParser()
    config.read("config.ini")
    return "-Djava.class.path=" + config["Settings"]["Path_to_Java_API"]