#!/bin/bash
export C_FORCE_ROOT=1
celery worker -A ipsec_agent.celery -P eventlet --loglevel=info &
python3 ipsec_agent.py