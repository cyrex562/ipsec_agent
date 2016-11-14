from multiprocessing import Process
#from flask_socketio import SocketIO, emit
import vici
import socket

def event_grabber_proc(url):
    #local_socketio = SocketIO(async_mode="threading")
    print("listening for log events from vici")
    #c = socket.socket(socket.AF_UNIX)
    #c.connect(b"/var/run/charon.vici")
    log_events = vici.Session().listen(event_types=[b"log", b"ike-updown", b"ike-rekey", b"child-updown", b"child-rekey", ])
    for log_event in log_events:
        print("log event: {}".format(log_event))
        log_event_dict = {
            "group": le["group"].decode("utf8"),
            "level": le["level"].decode("utf8"),
            "ikesa-name": le["ikesa-name"].decode("utf8"),
            "msg": le["msg"].decode("utf8")
            }
       #local_socketio.emit('log event', {'data': log_event_dict}, namespace='/ws/log_events')

def run():
    url = 'redis://localhost:6379/0'
    #egp = Process(target=event_grabber_proc, args=(url,))
    #egp.start()
    #egp.join()
    event_grabber_proc(url)

if __name__ == "__main__":
    run()