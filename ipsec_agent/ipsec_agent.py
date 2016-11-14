#!/usr/bin/python3
import vici
import socket
import json
#from bottle import route, run, get, post, put, delete, Bottle, request, abort, jinja2_view, TEMPLATE_PATH
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import logging
#from gevent import Greenlet
import gevent
#from gevent.pywsgi import WSGIServer
#from geventwebsocket import WebSocketError
#from geventwebsocket.handler import WebSocketHandler
#from socketio import socketio_manage
#from socketio.namespace import BaseNamespace
#from socketio.server import SocketIOServer
#from socketio.mixins import BroadcastMixin
import os
import binascii
from celery import Celery
import eventlet
import time
from datetime import timedelta
import sys
from celery.utils.log import get_task_logger
#from eventlet.green import socket
#eventlet.monkey_patch()
from multiprocessing import Process
import socket


app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["SECRET_KEY"] = binascii.hexlify(os.urandom(64))
app.debug = True

#sio = SocketIO(app, 
#               async_mode='eventlet', 
#               message_queue=app.config['SOCKETIO_REDIS_URL'])

sio = SocketIO(app, 
               async_mode='gevent', 
               message_queue=app.config['SOCKETIO_REDIS_URL'])

#celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
#celery.conf.update(app.config)

#TEMPLATE_PATH[:] = ['templates']

#app.logger = logging.getapp.logger()
#app.logger.setLevel(logging.DEBUG)

g_debug_enabled=True
g_reloader_enabled=True
g_listen_address="0.0.0.0"
g_listen_port=8010



#app = Bottle()
@app.route("/ipsec_agent", methods=["GET"])
def handle_ipsec_agent():
    return render_template("ipsec_agent.html", title="IPSEC agent")



@app.route('/ipsec/version', methods=["GET"])
def get_ipsec_version_route():
    s = vici.Session()
    version = s.version()
    app.logger.debug("version: {}".format(version))
    version_dict = {
            'daemon': version['daemon'].decode('utf8'),
            'version': version['version'].decode('utf8'),
            'sysname': version['sysname'].decode('utf8'),
            'release': version['release'].decode('utf8'),
            'machine': version['machine'].decode('utf8')
        }
    return json.dumps(version_dict)

@app.route('/js/<path:path>')
def handle_js_route(path):
    #app.send_from_directory('static/js/' + path)
    return app.send_static_file('js/' + path)


@app.route('/ipsec/stats', methods=["GET"])
def get_ipsec_stats_route():
    s = vici.Session()
    stats = s.stats()
    app.logger.debug("stats: {}".format(stats))
    stats_dict = {
        'uptime': {
            'running': stats['uptime']['running'].decode('utf8'),
            'since': stats['uptime']['since'].decode('utf8')},
        'ikesas': {
            'total': stats['ikesas']['total'].decode('utf8'),
            'half-open': stats['ikesas']['half-open'].decode('utf8')},
        'plugins': [ p.decode('utf8') for p in stats['plugins']]
        }
    return json.dumps(stats_dict)

@app.route('/ipsec/sas', methods=["GET"])
def get_ipsec_sas_route():
    sas = vici.Session().list_sas()
    _sas = []
    for sa in sas:
        app.logger.debug("sa: {}".format(sa))

        for s in sa.keys():
            child_sa_keys = sa[s]["child-sas"].keys()
            child_sas = []
            for k in child_sa_keys:
                local_ts_entries = [ltse.decode("utf8") for ltse in sa[s]["child-sas"][k]["local-ts"]]
                remote_ts_entries = [rtse.decode("utf8") for rtse in sa[s]["child-sas"][k]["remote-ts"]]
                child_sas.append(
                    { k: {"uniqueid": sa[s]["child-sas"][k]["uniqueid"].decode("utf8"),
                            "reqid": sa[s]["child-sas"][k]["reqid"].decode("utf8"),
                            "state": sa[s]["child-sas"][k]["state"].decode("utf8"),
                            "mode": sa[s]["child-sas"][k]["mode"].decode("utf8"),
                            "protocol": sa[s]["child-sas"][k]["protocol"].decode("utf8"),
                            "encap": sa[s]["child-sas"][k]["encap"].decode("utf8"),
                            "spi-in": sa[s]["child-sas"][k]["spi-in"].decode("utf8"),
                            "spi-out": sa[s]["child-sas"][k]["spi-out"].decode("utf8"),
                            "encr-alg": sa[s]["child-sas"][k]["encr-alg"].decode("utf8"),
                            "encr-keysize": sa[s]["child-sas"][k]["encr-keysize"].decode("utf8"),
                            "integ-alg": sa[s]["child-sas"][k]["integ-alg"].decode("utf8"),
                            "bytes-in": sa[s]["child-sas"][k]["bytes-in"].decode("utf8"),
                            "packets-in": sa[s]["child-sas"][k]["packets-in"].decode("utf8"),
                            "bytes-out": sa[s]["child-sas"][k]["bytes-out"].decode("utf8"),
                            "packets-out": sa[s]["child-sas"][k]["packets-out"].decode("utf8"),
                            "rekey-time": sa[s]["child-sas"][k]["rekey-time"].decode("utf8"),
                            "life-time": sa[s]["child-sas"][k]["life-time"].decode("utf8"),
                            "install-time": sa[s]["child-sas"][k]["install-time"].decode("utf8"),
                            "local-ts": local_ts_entries,
                            "remote-ts": remote_ts_entries}})
            _sas.append({ s : {
                'uniqueid': sa[s]['uniqueid'].decode('utf8'),
                'version': sa[s]['version'].decode('utf8'),
                'state': sa[s]['state'].decode('utf8'),
                'local-host': sa[s]['local-host'].decode('utf8'),
                'local-port': sa[s]['local-port'].decode('utf8'),
                'local-id': sa[s]['local-id'].decode('utf8'),
                'remote-host': sa[s]['remote-host'].decode('utf8'),
                'remote-port': sa[s]['remote-port'].decode('utf8'),
                'remote-id': sa[s]['remote-id'].decode('utf8'),
                'initiator': sa[s]['initiator'].decode('utf8'),
                'initiator-spi': sa[s]['initiator-spi'].decode('utf8'),
                'responder-spi': sa[s]['responder-spi'].decode('utf8'),
                'nat-local': sa[s]['nat-local'].decode('utf8'),
                'nat-remote': sa[s]['nat-remote'].decode('utf8'),
                'nat-any': sa[s]["nat-any"].decode("utf8"),
                "encr-alg": sa[s]["encr-alg"].decode("utf8"),
                "encr-keysize": sa[s]["encr-keysize"].decode("utf8"),
                "integ-alg": sa[s]["integ-alg"].decode("utf8"),
                "prf-alg": sa[s]["prf-alg"].decode("utf8"),
                "dh-group": sa[s]["dh-group"].decode("utf8"),
                "established": sa[s]["established"].decode("utf8"),
                "reauth-time": sa[s]["reauth-time"].decode("utf8"),
                "child-sas": child_sas}})

    return json.dumps(_sas)


@app.route('/ipsec/conns', methods=["GET"])
def get_ipsec_conns_route():
    conns = vici.Session().list_conns()
    _conns = []
    for conn in conns:
        app.logger.debug("conn: {}".format(conn))

        for k in conn.keys():
            local_addr_entries = [lae.decode("utf8") for lae in conn[k]["local_addrs"]]
            remote_addr_entries = [rae.decode("utf8") for rae in conn[k]["remote_addrs"]]
            _conns.append(
                {k: {"local_addrs": local_addr_entries,
                     "remote_addrs": remote_addr_entries,
                     "version": conn[k]["version"].decode("utf8"),
                     "reauth_time": conn[k]["reauth_time"].decode("utf8"),
                     "rekey_time": conn[k]["rekey_time"].decode("utf8"),
                     "locals": "",
                     "remotes": "",
                     "children": children}})
    return json.dumps(_conns)

#@celery.task()
#def background_task(url):
#    #logger = background_task.get_logger()
#    local_socketio = SocketIO(message_queue=url)
#    print("listening for log events from vici")
#    c = socket.socket(socket.AF_UNIX)
#    c.connect("/var/run/charon.vici")
#    log_events = vici.Session(c).listen(event_types=[b"log", b"ike-updown", b"ike-rekey", b"child-updown", b"child-rekey", ])
#    for log_event in log_events:
#        print("log event: {}".format(log_event))
#        log_event_dict = {
#            "group": le["group"].decode("utf8"),
#            "level": le["level"].decode("utf8"),
#            "ikesa-name": le["ikesa-name"].decode("utf8"),
#            "msg": le["msg"].decode("utf8")
#            }
#        local_socketio.emit('log event', {'data': log_event_dict}, namespace='/ws/log_events')



def event_grabber_proc(url):
    local_socketio = SocketIO(message_queue=url)
    print("listening for log events from vici")
    #c = socket.socket(socket.AF_UNIX)
    #c.connect("/var/run/charon.vici")
    log_events = vici.Session().listen(event_types=[b"log", b"ike-updown", b"ike-rekey", b"child-updown", b"child-rekey", ])
    for log_event in log_events:
        print("log event: {}".format(log_event))
        log_event_dict = {
            "group": le["group"].decode("utf8"),
            "level": le["level"].decode("utf8"),
            "ikesa-name": le["ikesa-name"].decode("utf8"),
            "msg": le["msg"].decode("utf8")
            }
        local_socketio.emit('log event', {'data': log_event_dict}, namespace='/ws/log_events')

#@app.route('/ipsec/log_events')
#def start_log_events():
#    background_task.delay(app.config['SOCKETIO_REDIS_URL'])
#    return 'started'

# run code #
#run(app=app, host=g_listen_address, port=g_listen_port, reloader=g_reloader_enabled, debug=True)

#server = WSGIServer((g_listen_address, g_listen_port), 
#                    app, 
#                    handler_class=WebSocketHandler)
#server.serve_forever()

#run(app=app, host=g_listen_address, port=g_listen_port, reloader=g_reloader_enabled, debug=g_debug_enabled, server='geventSocketIO')

#server = WSGIServer((g_listen_address, g_listen_port), app)
#server.serve_forever

if __name__ == "__main__":
    url = app.config['SOCKETIO_REDIS_URL']
    egp = Process(target=event_grabber_proc, args=(url,))
    egp.start()
    sio.run(app, host=g_listen_address, port=g_listen_port, debug=g_debug_enabled)
    # TODO: cancel the event grabbing process
    egp.join()
# END OF FILE #