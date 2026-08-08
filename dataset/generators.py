"""
===========================================================
CloudShield AI
Dataset Row Generators
===========================================================

Generates realistic cybersecurity telemetry
for CloudShield AI.
"""

import config
import utils


# ===========================================================
# COMMON ROW
# ===========================================================

def build_row(profile, attack_type):

    protocol = utils.random_protocol()

    # -------------------------------------------------------
    # Source IP
    # -------------------------------------------------------

    if attack_type == "Normal":

        source_ip = utils.normal_ip()

    else:

        source_ip = utils.attacker_ip()

    # -------------------------------------------------------
    # Timestamp
    # -------------------------------------------------------

    if attack_type == "DDoS":

        timestamp = utils.ddos_timestamp()

    else:

        timestamp = utils.random_timestamp()

    # -------------------------------------------------------
    # System Metrics
    # -------------------------------------------------------

    cpu = utils.cpu_usage(profile["cpu"])

    memory = utils.memory_usage(cpu)

    response = utils.response_time(cpu)

    # -------------------------------------------------------
    # Build Row
    # -------------------------------------------------------

    return {

        "Timestamp": timestamp,

        "Source IP": source_ip,

        "Destination IP": utils.destination_ip(),

        "Protocol": protocol,

        "Port": utils.protocol_port(protocol),

        "Packets": utils.packets(profile["packets"]),

        "Bytes": utils.bytes_transferred(profile["bytes"]),

        "Request Count": utils.request_count(profile["request_count"]),

        "Login Attempts": utils.login_attempts(profile["login_attempts"]),

        "CPU Usage": cpu,

        "Memory Usage": memory,

        "Response Time": response,

        "Attack Type": attack_type,

        "Label": config.LABELS[attack_type]

    }


# ===========================================================
# NORMAL
# ===========================================================

def generate_normal():

    return build_row(

        config.NORMAL,

        "Normal"

    )


# ===========================================================
# BRUTE FORCE
# ===========================================================

def generate_brute_force():

    return build_row(

        config.BRUTE_FORCE,

        "Brute Force"

    )


# ===========================================================
# SQL INJECTION
# ===========================================================

def generate_sql_injection():

    return build_row(

        config.SQL_INJECTION,

        "SQL Injection"

    )


# ===========================================================
# DDOS
# ===========================================================

def generate_ddos():

    return build_row(

        config.DDOS,

        "DDoS"

    )


# ===========================================================
# PORT SCAN
# ===========================================================

def generate_port_scan():

    return build_row(

        config.PORT_SCAN,

        "Port Scan"

    )


# ===========================================================
# CREDENTIAL STUFFING
# ===========================================================

def generate_credential_stuffing():

    return build_row(

        config.CREDENTIAL_STUFFING,

        "Credential Stuffing"

    )