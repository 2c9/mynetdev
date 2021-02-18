
import time
import paramiko

class Switch:
    
    cmdprompt = '#'

    def connect(self, ipaddr, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( hostname=ipaddr, username=username, password=password, look_for_keys=False, allow_agent=False)
            self.ssh = client.invoke_shell(width=512)
            self.ssh.settimeout(5)
            self.ssh.recv(3000)
        except:
            raise Exception('SSHConnectionFailed')
    
    def ssh_read(self):
        self.ssh.settimeout(5)
        output=''
        part=''
        while True:
            try:
                part=self.ssh.recv(3000).decode('utf-8')
                time.sleep(0.5)
                output+=part
                if output[-1*len(self.cmdprompt):] == self.cmdprompt:
                    break
            except socket.timeout:
                    break
        return output
