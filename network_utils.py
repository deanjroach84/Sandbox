# network_utils.py

import socket
import json
from time import sleep
from models import db, Scan
from app import app  # import your Flask app instance

def scan_ports_thread(scan_id):
    """
    Thread target function to perform a port scan and update the Scan record in DB.
    """
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return  # Scan not found, just return

        open_ports = []
        start_port = scan.start_port
        end_port = scan.end_port
        target_ip = scan.target_ip

        total_ports = end_port - start_port + 1
        scanned_ports = 0

        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                try:
                    if s.connect_ex((target_ip, port)) == 0:
                        open_ports.append(port)
                except Exception:
                    pass
                scanned_ports += 1

            # Optional: update progress intermittently (every 10 ports or so)
            if scanned_ports % 10 == 0 or scanned_ports == total_ports:
                scan.open_ports = json.dumps(open_ports)
                db.session.commit()
                sleep(0.01)  # small sleep to yield control

        # Final update with complete results
        scan.open_ports = json.dumps(open_ports)
        db.session.commit()
