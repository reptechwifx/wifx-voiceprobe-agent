"""Observe Linux address/route changes outside the PJSIP event thread."""
import ipaddress
import threading
from telemetry import network_snapshot


def network_key(snapshot):
    addresses = []
    for interface in snapshot.get('interfaces', []):
        if not interface.get('up'):
            continue
        for value in interface.get('addresses', []):
            try:
                address = ipaddress.ip_address(value['address'])
            except (KeyError, ValueError):
                continue
            if not (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast):
                addresses.append((interface.get('name'), str(address)))
    return (tuple(sorted(addresses)), snapshot.get('primary_interface'), snapshot.get('gateway'),
            tuple(snapshot.get('dns', [])))


class NetworkMonitor:
    def __init__(self, notify, interval=2, reader=network_snapshot):
        self.notify, self.interval, self.reader = notify, interval, reader
        self.stop_event = threading.Event()
        self.previous = None

    def sample(self):
        current = network_key(self.reader())
        previous, self.previous = self.previous, current
        if previous is not None and current != previous:
            self.notify(bool(current[0]))

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.sample()
            except (OSError, ValueError):
                pass
            self.stop_event.wait(self.interval)

    def stop(self):
        self.stop_event.set()
