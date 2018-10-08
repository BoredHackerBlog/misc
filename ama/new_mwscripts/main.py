import time, threading, minimega, os, filetracker
from random import randint

#Edit this stuff
mm_loc = "/home/mw/minimega/bin/minimega"
debugging = True
outdir="/out/" #folder for results
filedir="/opt/malware/unsorted/PE32/" #location where the exe files are stored
basexp = "/home/mw/xp_e1000.qc2" #xp image
baseinet = "/home/mw/inetsim.qc2" #inetsim image
netlist = [] #to keep track of vm_net numbers

def dbg(message):
	if (debugging==True):
		print "Debug message:*****" + message + "*****"

dbg("started")

def setup():
	dbg("setup started")
	dbg("starting minimega")
	os.system(mm_loc + " -nostdin &")
	dbg("modprobing nbd")
	os.system("modprobe nbd max_part=10")
	dbg("making dirs")
	os.system("mkdir /mnt/1")
	os.system("mkdir /mnt/2")
	os.system("mkdir /out")
	time.sleep(10)
	dbg("connecting to minimega")
	global mm1
	mm1 = minimega.connect("/tmp/minimega/minimega")
	mm1.optimize(ksm=True)
	dbg("connected")


config_lock = threading.Lock()
inject_lock = threading.Lock()
extract_lock = threading.Lock()

def inject(imgin, imgout, file):
	inject_lock.acquire()
	try:
		dbg("starting injection")
		mm1.vm_inject(str(imgin), str(imgout), str(file))
		dbg("done injecting")
	finally:
		inject_lock.release()

def config_start(net, inetloc, winloc, inetname, winname):
	config_lock.acquire()
	try:
		dbg("configuring and starting VMs")
		mm1.vm_net(str(net))
		mm1.vm_memory(512)
		mm1.vm_snapshot(False)
		mm1.vm_disk(str(inetloc))
		mm1.vm_launch(str(inetname))
		mm1.vm_start(str(inetname))
		dbg("started inetsim")
		time.sleep(10)
		mm1.vm_disk(str(winloc))
		mm1.vm_launch(str(winname))
		mm1.vm_start(str(winname))
		dbg("started windows")
		mm1.clear("vm_config")
	finally:
		config_lock.release()

def killvms(inetname, winname):
	dbg("killing VMs")
	mm1.vm_kill(str(inetname))
	mm1.vm_kill(str(winname))
	mm1.vm_flush()
	dbg("VMs killed")

def extract(inetloc, winloc, resdir):
	extract_lock.acquire()
	try:
		dbg("extracting results")
		os.system("qemu-nbd -c /dev/nbd7 " + inetloc)
		os.system("qemu-nbd -c /dev/nbd8 " + winloc)
		os.system("mount /dev/nbd7p1 /mnt/1")
		os.system("mount /dev/nbd8p1 /mnt/2")
		os.system("cp /mnt/2/proclog.csv " + outdir + resdir + "/proclog.csv")
		os.system("cp /mnt/1/var/log/inetsim/service.log " + outdir + resdir + "/inetsim.log")
		dbg("done extracting")
		dbg("cleaning up")
		os.system("umount /mnt/1")
		os.system("umount /mnt/2")
		os.system("qemu-nbd -d /dev/nbd7")
		os.system("qemu-nbd -d /dev/nbd8")
		os.system("rm " + inetloc)
		os.system("rm " + winloc)
		dbg("done cleaning up")
	finally:
		extract_lock.release()

def screenshot(winname, resdir):
	dbg("taking a screenshot")
	mm1.vm_qmp(str(winname), { "execute":"screendump", "arguments":{"filename": str(outdir + resdir) + "/screenshot.ppm" } })

def pcap(winname, resdir):
	#fix this
	dbg("capturing packets")
	mm1.capture("pcap", "vm", str(winname), "0", str(outdir+resdir) + "/packets.pcap")

def memdump(winname, resdir):
	dbg("dumping the memory")
	mm1.vm_qmp(str(winname), { "execute":"pmemsave", "arguments":{"val": 0, "size": 512000000, "filename": str(outdir + resdir) + "/memdump.dump" }} )

def stopmm():
	dbg("Killing minimega")
	mm1.quit()

def runsim(pefile, net):
	#clean this up, use a list or an array to store this stuff
	resdir = pefile+"_results/"
	xpout = "xp_"+pefile+".qc2"
	inetout = "inet_"+pefile+".qc2"
	xpfile = filedir+pefile+":sample/mal.exe"
	xpinjected = "/tmp/minimega/files/xp_"+pefile+".qc2"
	inetinjected = "/tmp/minimega/files/inet_"+pefile+".qc2"
	xpname = "xp_"+pefile
	inetname = "inet_"+pefile

	dbg("making dir")
	os.system("mkdir "+outdir+resdir)
	dbg("main: running simulation")
	filetracker.status_update(pefile,"processing")
	dbg("main: appended net number")
	netlist.append(net)
	dbg("main: injecting files")
	inject(basexp, xpout, xpfile)
	inject(baseinet+":1", inetout, " ")
	dbg("main: called config_start")
	config_start(net, inetinjected, xpinjected, inetname, xpname)
#	dbg("main: starting packet capture")
#	pcap(xpname, resdir) #doesn't work
	time.sleep(150)
	dbg("main: screenshotting")
	screenshot(xpname,resdir)
	time.sleep(60)
	dbg("main: dumping mem")
	memdump(xpname, resdir)
	dbg("main: killing VMs")
	killvms(inetname, xpname)
	time.sleep(10)
	dbg("main: removing net number")
	netlist.remove(net)
	dbg("main: extracting data")
	extract(inetinjected, xpinjected, resdir)
	filetracker.status_update(pefile,"done")

def netnum():
	dbg("generating net numb")
	numb = randint(1,10)
	while (numb in netlist):
		numb = randint(1,10)
	return numb

setup()
time.sleep(10)

t1 = threading.Thread()
t2 = threading.Thread()

while True:
#	qfile = open('quit','r')
#	if (qfile.read() = "quit\n"):
#		While (t1.isAlive() and t2.isAlive()):
#			time.sleep(30)
#		stopmm()
#		quit()
#	qfile.close()
	if (filetracker.next() != None):
		dbg("next is not empty - t1")
		if (t1.isAlive() == False):
			dbg("t1 is not alive")
			dbg("starting t1")
			t1 = threading.Thread(target=runsim, args=(filetracker.next(),netnum(),))
			t1.start()
			dbg("t1 started")
			time.sleep(5)
	if (filetracker.next() != None):
		dbg("next is not empty - t2")
		if (t2.isAlive() == False):
			dbg("t2 is not alive")
			dbg("starting t2")
			t2 = threading.Thread(target=runsim, args=(filetracker.next(),netnum(),))
			t2.start()
			dbg("t2 started")
	        	time.sleep(5)
	time.sleep(60)
