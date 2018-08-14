# Copyright (c) 2015 Vikas Iyengar, iyengar.vikas@gmail.com (http://garage4hackers.com)
# Copyright (c) 2016 Detux Sandbox, http://detux.org
# See the file 'COPYING' for copying permission.

import pexpect
import paramiko
import time
from ConfigParser import ConfigParser
from hashlib import sha256
from magic import Magic
import os
import random

class Sandbox:
    def __init__(self, config_path):
        self.config = ConfigParser()
        self.config.read(config_path)
        self.default_cpu = self.config.get("detux", "default_cpu")
        
    def execute(self, binary_filepath, platform, sandbox_id, interpreter = None):
        sandbox_starttime = time.time()
        sandbox_endtime   = sandbox_starttime
        vm_exec_time = self.config.getint("detux", "vm_exec_time")
        qemu_command = self.qemu_commands(platform, sandbox_id) 
        pcap_folder = self.config.get("detux", "pcap_folder")
        if not os.path.isdir(pcap_folder):
            os.mkdir(pcap_folder)
        ssh_host = self.config.get(platform+"-"+sandbox_id, "ip")
        ssh_user = self.config.get(platform+"-"+sandbox_id, "user")
        macaddr  = self.config.get(platform+"-"+sandbox_id, "macaddr")
        ssh_password = self.config.get(platform+"-"+sandbox_id, "password")
        ssh_port  = self.config.getint(platform+"-"+sandbox_id, "port")
        pcap_command = "sudo /usr/bin/dumpcap -i %s -P -w %s -f 'not ((tcp dst port %d and ip dst host %s) or (tcp src port %d and ip src host %s))'"
        # A randomly generated sandbox filename       
        dst_binary_filepath = "Sample2/" + ("".join(chr(random.choice(xrange(97,123))) for _ in range(random.choice(range(6,12)))))
        sha256hash = sha256(open(binary_filepath, "rb").read()).hexdigest()
        interpreter_path = { "python" : "/usr/bin/python", "perl" : "/usr/bin/perl", "sh" : "/bin/sh", "bash" : "/bin/bash"  }
        if qemu_command == None :
            return {}
        qemu_command += " -net nic,macaddr=%s -net tap -monitor stdio" % (macaddr,)  
        print qemu_command   
        qemu = pexpect.spawn(qemu_command)
        try: 	
            qemu.expect("(qemu).*")
            qemu.sendline("info network")
            qemu.expect("(qemu).*")
	    print "chao cac ban"
            ifname =  qemu.before.split("ifname=", 1)[1].split(",", 1)[0]
            qemu.sendline("loadvm kien2")
            qemu.expect("(qemu).*")
            print qemu.before	  
            pre_exec  = {}
            post_exec = {}
            #pre_exec  = self.ssh_execute(ssh_host, ssh_port, ssh_user, ssh_password, ["netstat -an", "ps aux"])

            # Wait for the snapshot to be restored and then transfer the binary
            time.sleep(5)
            print qemu.before
	    #truyen file tu may that vao may ao MIPS thong qua ftp. 
            self.scp(ssh_host, ssh_port, ssh_user, ssh_password, binary_filepath, dst_binary_filepath)
            print "[+] Binary transferred"
            
            # Pre binary execution commands
	    # Gan quyen thuc thi cho file moi duoc truyen vao may ao .
            pre_exec  = self.ssh_execute(ssh_host, ssh_port, ssh_user, ssh_password, ["chmod a+x %s" % (dst_binary_filepath,)])

	    #Tao thu muc de luu du lieu strace
	    pre_exec2  = self.ssh_execute(ssh_host, ssh_port, ssh_user, ssh_password, "mkdir stracelog");
            # Start Packet Capture
            pcap_filepath = os.path.join(pcap_folder, "%s_%d.cap" %(sha256hash,time.time(),))
            pcapture = pexpect.spawn(pcap_command % (ifname, pcap_filepath, ssh_port, ssh_host, ssh_port, ssh_host))
	    print pcap_command % (ifname, pcap_filepath, ssh_port, ssh_host, ssh_port, ssh_host)
            print "[+] Packet Capture started"
            
            # Wait for pcapture to start and then Execute the binary
            time.sleep(5)
            
	    # Get systemcall by strace 
	    #Tao ra 1 ten file tuong ung voi duong dan file chay de ghi lai du lieu strace.
	    #Thu muc luu tru output cua strace la thu muc Strace.
	    
	    
	    #Tao ra ten file de ghi file strace (ben trong thu muc log)
	    (head, filename_write) = os.path.split(binary_filepath)

	    #Chay lenh strace tren file da duoc truyen vao trong may ao.
	    #Dau tien ta tao ra 1 command strace sau do thuc thi command do.
	    #Ghi du lieu strace vao thu muc stracelog ben trong may ao sau do ssh de lay du lieu ma may that
	    command_to_exec="timeout 120 strace -ff -o stracelog/%s ./%s" % (filename_write,dst_binary_filepath,)
            print "[+] Executing %s" % (command_to_exec,)

            exec_ssh = self.ssh_executeStrace(ssh_host, ssh_port, ssh_user, ssh_password, command_to_exec,filename_write,True, False )

	    #exec_ls=self.ssh_executeLs(ssh_host, ssh_port, ssh_user, ssh_password,"ls")

            starttime = time.time()
	    print "get file from virtual machine"
	    self.getFile(ssh_host, ssh_port, ssh_user, ssh_password, filename_write)
	    print "done"	

            while  time.time() < starttime + vm_exec_time:
                if not qemu.isalive():
                    vm_exec_time = 0
            if qemu.isalive():
                # Post binary execution commands
                post_exec = self.ssh_execute(ssh_host, ssh_port, ssh_user, ssh_password, ["ps aux"])
                try:
                    if exec_ssh <> None:
                        exec_ssh.close()
                except Exception as e:
                    print "[+] Error while logging out exec_ssh: %s" % (e,)            
                qemu.sendline("q")
           
            # Stop Packet Capture
            if pcapture.isalive():
                pcapture.close()

            sandbox_endtime = time.time()
            result = {'start_time' : sandbox_starttime, 'end_time' : sandbox_endtime, 'pcap_filepath' : pcap_filepath}
            result['post_exec_result'] = post_exec
            result['cpu_arch'] = platform
            result['interpreter'] = interpreter
        except Exception as e:
            print "[-] Error:", e
            if qemu.isalive():
                qemu.close()
            return {}
        
        return result

        
    def identify_platform(self, filepath):
        filemagic = Magic()
        filetype = ""
        try:
            filetype = filemagic.id_filename(filepath)
        except Exception as e:
            # certain version of libmagic throws error while parsing file, the CPU information is however included in the error in somecases
            filetype = str(e)
#        filemagic.close()
        if "ELF 32-bit" in filetype: 
            if "ARM" in filetype:
                return "ELF", "arm"
            if "80386" in filetype:
                return "ELF", "x86"
            if ("MIPS" in filetype) and ("MSB" in filetype):
                return "ELF", "mips"
            if "MIPS" in filetype:
                return "ELF", "mipsel"
            if "PowerPC" in filetype:
                return "ELF", "powerpc"
        if "ELF 64-bit" in filetype:
            if "x86-64" in filetype:
                return "ELF", "x86-64"


        return filetype, self.default_cpu


    def qemu_commands(self, platform, sandbox_id):
        if platform == "x86":
            return "sudo qemu-system-i386 -hda qemu/x86/%s/debian_wheezy_i386_standard.qcow2 -vnc 127.0.0.1:1%s" % (sandbox_id, sandbox_id, )
        if platform == "x86-64":
            return "sudo qemu-system-x86_64 -hda qemu/x86-64/%s/debian_wheezy_amd64_standard.qcow2 -vnc 127.0.0.1:2%s" % (sandbox_id, sandbox_id,)
        if platform == "mips":
            return 'sudo qemu-system-mips -M malta -kernel qemu/mips/%s/vmlinux-3.2.0-4-4kc-malta -hda qemu/mips/%s/debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1 console=tty0" -vnc 127.0.0.1:3%s'  % (sandbox_id, sandbox_id, sandbox_id,)
        if platform == "mipsel":
            return 'sudo qemu-system-mipsel -M malta -kernel qemu/mipsel/%s/vmlinux-3.2.0-4-4kc-malta -hda qemu/mipsel/%s/debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -vnc 127.0.0.1:4%s'  % (sandbox_id, sandbox_id, sandbox_id, )
        if platform == "arm":
            return 'sudo qemu-system-arm -M versatilepb -kernel qemu/arm/%s/vmlinuz-3.2.0-4-versatile -initrd qemu/arm/%s/initrd.img-3.2.0-4-versatile -hda qemu/arm/%s/debian_wheezy_armel_standard.qcow2 -append "root=/dev/sda1" -vnc 127.0.0.1:5%s'  % (sandbox_id, sandbox_id, sandbox_id, sandbox_id,)
        return None


    #Ham chay 1 command tren may ao thong qua ssh.
    #Dau tien tao 1 ssh client sau do ket noi toi may ao va chay command.
    def ssh_execute(self, host, port, user, password, commands, noprompt = False, logout = True):
        result = None
	output=""
	#Tao 1 ssh client.
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
	    #Ket noi ssh toi may ao.
            ssh.connect(host, port=port, username=user, password=password)
	    #Truong hop chi chay 1 command.
            if type(commands) == type(str()):
		#Chay command tren may ao thong qua ssh, timeout=10s
                stdin, stdout, stderr  = ssh.exec_command(commands, timeout=40)

                if noprompt == False:    
                    result = "".join(stdout.readlines())
	    #Truong hop nhap vao 1 list command.
            if type(commands) == type(list()):
                result = {}
                for command in commands:
		    #chay lan luot tung command thong qua ssh.
                    stdin, stdout, stderr  = ssh.exec_command(command, timeout=40)
                    result[command] = "".join(stdout.readlines())
            if logout:
                ssh.close()
            else:
                return ssh # Return SSH object to logout later
        except Exception as e:
            print "[+] Error in ssh_execute: %s" % (e,)
        return result

    # Ham dung de chay strace va ghi lai ket qua vao file text 
    # Dau tien tao 1 client sau do ket noi toi may ao MIPS va thuc thi command strace
    def ssh_executeStrace(self, host, port, user, password, commands,filename_write,noprompt = False, logout = True):
        result = None
	output=""
	#Tao 1 ssh client.
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
	    #ket noi toi may ao thong qua ssh.
            ssh.connect(host, port=port, username=user, password=password)
            if type(commands) == type(str()):
		#Thuc thi 1 command trong may ao MIPS, timeout=10s
		#Mot so file khong chay duoc strace
                stdin, stdout, stderr  = ssh.exec_command(commands, timeout=120)
		
		print "------------------------------------------"
		
		#Doc ket qua sau khi chay strace tu luong xuat loi chuan(stderr)
		#Khi doc tu luong ra chuan(stdout) ket qua khong nhu mong doi, Vi du khi chay lenh strace ls thi ket qua giong nhu khi chay ls, khong hien ra systemcall ma lai hien danh sach thu muc. 
		#stderr=stderr.readlines();
		#for line in stderr:
    		#	output=output+line

		#in ra ket qua strace ra man hinh de quan sat.
		#print output

		#ghi lai output cua strace vao duong dan file text da truyen vao
		#file=open(filename_write,'w')
		#file.write(output)
		#file.close
		
		print "Strace log was written in :"+filename_write;

                if noprompt == False:    
                    result = "".join(stdout.readlines())
            if logout:
                ssh.close()
            else:
                return ssh # Return SSH object to logout later
        except Exception as e:
            print "[+] Error in ssh_execute: %s" % (e,)
        return result


    
	#Ham dung de truyen file tu may that vao may ao MIPS
	#Dau tien tao 1 ssh Client sau do ket noi toi may ao va truyen file vao duong dan dst_file tren may ao.
    def scp(self, host, port, user, password, src_file, dst_file):
	#tao 1 ssh client.
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
	    #ket noi ssh toi may ao.
            ssh.connect(host, port=port, username=user, password=password)
	    # Truyen file vao may ao thong qua ftp.
            sftp = ssh.open_sftp()
            sftp.put(src_file, dst_file)

        except Exception as e:
            print "[+] Error in scp: %s" % (e,)

  
    def getFile(self, host, port, user, password,src_file):
	ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
        try:
	    #ket noi ssh toi may ao.
            ssh.connect(host, port=port, username=user, password=password)
	    command = 'find stracelog/ -name "*"'
	    stdin, stdout, stderr = ssh.exec_command(command)
	    filelist = stdout.read().splitlines()

	    # get file log tu may
            sftp = ssh.open_sftp()
            for afile in filelist:
		if (afile!="stracelog/"):
			(head, filename) = os.path.split(afile)
			print filename
    	    		sftp.get(afile, "log/"+filename)

        except Exception as e:
            print "[+] Error in scp: %s" % (e,)  
   

         
