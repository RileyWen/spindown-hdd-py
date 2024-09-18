#!/usr/bin/env python3

import os
import time
import json
import signal
import subprocess
import logging
from pathlib import Path
import sys

# Default configuration file
CONFIG = os.getenv("CONFIG", "/etc/hdd-spindown.json")

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
logger = logging.getLogger('hdd-spindown')

# Flag to indicate when to stop the loop
running = True

# Helper functions
def run_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode()

def check_requirements(commands):
    missing = [cmd for cmd in commands if subprocess.run(f'which {cmd}', shell=True, stdout=subprocess.PIPE).returncode != 0]
    if missing:
        logger.error(f"Missing executables in PATH: {', '.join(missing)}")
        exit(1)

def dev_stats(device):
    stat_path = f"/sys/block/{device}/stat"
    if not Path(stat_path).is_file():
        return None
    with open(stat_path) as f:
		# R_IO R_M R_S R_T W_IO REST
        data = f.read().split()
        return int(data[0]), int(data[4])  # Read I/O and Write I/O

def is_device_active(device):
    cmd = f"smartctl -i -n standby /dev/{device}"
    _, output = run_command(cmd)
    return "ACTIVE" in output or "IDLE" in output

def spindown_device(device):
    logger.info(f"Suspending {device}")
    cmd = f"hdparm -qy /dev/{device}"
    if run_command(cmd)[0] != 0:
        logger.error(f"Failed to suspend {device}")

def spinup_device(device, read_len):
    if is_device_active(device):
        return
    logger.info(f"Spinning up {device}")
    cmd = f"dd if=/dev/{device} of=/dev/null bs=1M count={read_len} iflag=direct"
    run_command(cmd)

def monitor_hosts(hosts):
    for host in hosts:
        cmd = f"ping -c 1 -q {host}"
        if run_command(cmd)[0] == 0:
            logger.info(f"Active host detected: {host}")
            return True
    logger.info("All hosts inactive")
    return False

# Load JSON configuration
def load_config(config_file):
    if not Path(config_file).is_file():
        logger.error(f"Unable to read config file {config_file}")
        exit(1)

    with open(config_file, 'r') as f:
        return json.load(f)

# Graceful exit handler for SIGINT (Ctrl + C)
def signal_handler(sig, frame):
    global running
    logger.info("SIGINT received, shutting down gracefully...")
    running = False

# Main logic
def main():
    global running
    
    # Register the signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    config = load_config(CONFIG)

    check_requirements(['hdparm', 'smartctl', 'dd', 'ping'])

    # Devices are now a list of dictionaries with 'device' and 'timeout' keys
    devices = [(d['device'], d['timeout']) for d in config.get('CONF_DEV', [])]
    interval = config.get('CONF_INT', 300)
    read_len = config.get('CONF_READLEN', 128)
    hosts = config.get('CONF_HOSTS', [])

    last_stats = {}
    user_present = False

    while running:  # The loop will run until SIGINT is received
        # Check if any monitored hosts are online (user presence detection)
        if hosts:
            user_present = monitor_hosts(hosts)

        for device, timeout in devices:
            current_stats = dev_stats(device)
            if current_stats is None:
                logger.warning(f"Skipping missing device: {device}")
                continue

            r_io = current_stats[0]
            w_io = current_stats[1]
            logger.debug(f"Device {device} R_IO {r_io}, W_IO {w_io}")

            if user_present:
                spinup_device(device, read_len)

            last_device_stats = last_stats.get(device)

            # If stats haven't changed since the last check, consider spindown
            if last_device_stats and current_stats == last_device_stats['stats']:
                idle_time = time.time() - last_device_stats['timestamp']
                if idle_time >= timeout and not user_present:
                    if not is_device_active(device):
                        logger.debug(f"Device {device} is not active or " + \
                                      "not able to query standby status.")
                    spindown_device(device)
            else:
                # Update stats and timestamp
                last_stats[device] = {'stats': current_stats, 'timestamp': time.time()}

        # Sleep for the configured interval before next check, unless interrupted
        for _ in range(interval):
            if not running:  # Break sleep early if SIGINT is received
                break
            time.sleep(1)

    logger.info("Shutdown complete.")

if __name__ == "__main__":
    main()

