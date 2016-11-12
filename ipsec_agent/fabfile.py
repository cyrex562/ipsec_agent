from fabric.api import local, settings, abort, run, cd, env, sudo, put
import os

env.hosts = ['home-gw']
env.password = "3c*7DJsu"
env.use_ssh_config = True

code_dir = "/opt/perfecta/ipsec_agent"

def make_dirs():
    sudo("mkdir -p %s" % code_dir)
    sudo("mkdir -p /var/log/perfecta")
    sudo("mkdir -p %s/static/css" % code_dir)
    sudo("mkdir -p %s/static/html" % code_dir)
    sudo("mkdir -p %s/static/img" % code_dir)
    sudo("mkdir -p %s/static/js" % code_dir)
    sudo("mkdir -p %s/templates" % code_dir)

def install_depends():
    put("requirements.txt", code_dir, use_sudo=True)
    sudo("apt -y install supervisor redis-server redis-tools")
    sudo("pip3 install -r %s/requirements.txt" % code_dir)

def deploy(restart_supervisor="no"):
    with cd(code_dir):
        put("ipsec_agent.py", code_dir, use_sudo=True)
        put("config.cfg", code_dir, use_sudo=True)
        put("start.sh", code_dir, use_sudo=True)
        put("templates/*", "templates", use_sudo=True)
        put("static/js/*", "static/js", use_sudo=True)
        sudo("chmod +x %s/ipsec_agent.py" % code_dir)
        sudo("chmod +x %s/start.sh" % code_dir)
        sudo("dos2unix *")
        sudo("dos2unix templates/*")
        sudo("dos2unix static/js/*")

    put("ipsec_agent.conf", "/etc/supervisor/conf.d", use_sudo=True)
    sudo("dos2unix /etc/supervisor/conf.d/ipsec_agent.conf")
    
    if restart_supervisor == "yes":
        print("restarting supervisor")
        sudo("supervisorctl reread")
        sudo("supervisorctl reload")
    

def test_rest():
    print("testing GET /ipsec/version")
    local("curl http://10.249.0.1:8010/ipsec/version")
    
    print("testing GET /ipsec/stats")
    local("curl http://10.249.0.1:8010/ipsec/stats")

    print("testing GET /ipsec/sas")
    local("curl http://10.249.0.1:8010/ipsec/sas")

# END OF FILE #
