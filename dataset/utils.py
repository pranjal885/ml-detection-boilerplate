"""
===========================================================
CloudShield AI
Utility Functions
===========================================================

Reusable helper functions for generating
synthetic cybersecurity data.
"""

import random
from datetime import datetime, timedelta

import config

# ===========================================================
# RANDOM SEED
# ===========================================================

random.seed(config.RANDOM_SEED)

# ===========================================================
# DDOS BURST STATE
# ===========================================================

_ddos_start = datetime.now() - timedelta(days=2)
_ddos_counter = 0

# ===========================================================
# RANDOM TIMESTAMP
# ===========================================================

def random_timestamp(days=30):

    now = datetime.now()

    start = now - timedelta(days=days)

    seconds = random.randint(
        0,
        int((now - start).total_seconds())
    )

    ts = start + timedelta(seconds=seconds)

    return ts.strftime("%Y-%m-%d %H:%M:%S")


# ===========================================================
# DDOS BURST TIMESTAMP
# ===========================================================

def ddos_timestamp():

    global _ddos_counter

    ts = _ddos_start + timedelta(
        seconds=_ddos_counter * config.DDOS_TIME_GAP_SECONDS
    )

    _ddos_counter += 1

    return ts.strftime("%Y-%m-%d %H:%M:%S")


# ===========================================================
# NORMAL USER IP
# ===========================================================

def normal_ip():

    return random.choice(config.NORMAL_IP_POOL)


# ===========================================================
# ATTACKER IP
# ===========================================================

def attacker_ip():

    return random.choice(config.ATTACKER_IP_POOL)


# ===========================================================
# DESTINATION IP
# ===========================================================

def destination_ip():

    return config.SERVER_IP


# ===========================================================
# WEIGHTED PROTOCOL
# ===========================================================

def random_protocol():

    return random.choices(

        population=config.PROTOCOLS,

        weights=[
            config.PROTOCOL_WEIGHTS["HTTP"],
            config.PROTOCOL_WEIGHTS["HTTPS"]
        ],

        k=1

    )[0]


# ===========================================================
# RANDOM PORT
# ===========================================================

def protocol_port(protocol):

    return random.choice(config.PORTS[protocol])


# ===========================================================
# RANDOM INTEGER
# ===========================================================

def random_int(value_range):

    return random.randint(

        value_range[0],

        value_range[1]

    )


# ===========================================================
# RANDOM FLOAT
# ===========================================================

def random_float(value_range):

    return round(

        random.uniform(

            value_range[0],

            value_range[1]

        ),

        2

    )


# ===========================================================
# NETWORK METRICS
# ===========================================================

def packets(value_range):

    return random_int(value_range)


def bytes_transferred(value_range):

    return random_int(value_range)


def request_count(value_range):

    return random_int(value_range)


def login_attempts(value_range):

    return random_int(value_range)


# ===========================================================
# CORRELATED CPU
# ===========================================================

def cpu_usage(value_range):

    return random_float(value_range)


# ===========================================================
# CORRELATED MEMORY
# ===========================================================

def memory_usage(cpu):

    variation = random.uniform(-8, 8)

    memory = cpu + variation

    memory = max(10, min(memory, 100))

    return round(memory, 2)


# ===========================================================
# CORRELATED RESPONSE TIME
# ===========================================================

def response_time(cpu):

    base = cpu * random.uniform(8, 18)

    noise = random.uniform(-40, 40)

    response = max(20, base + noise)

    return round(response, 2)


# ===========================================================
# SHUFFLE
# ===========================================================

def shuffle_dataset(rows):

    random.shuffle(rows)

    return rows