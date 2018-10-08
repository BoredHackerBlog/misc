import sqlite3, threading, time, os.path


def setup_db():
	global conn
	if (os.path.isfile("analysis_status.db") == False):
		conn = sqlite3.connect("analysis_status.db", check_same_thread=False)
		conn.execute("create table filetrack(fhash, status)") #status: processing, done, inline
		conn.commit()
	if (os.path.isfile("analysis_status.db") == True):
		conn = sqlite3.connect("analysis_status.db", check_same_thread=False)

def inlist(hash): #check if the file is already on the list or not
	outcome = conn.execute("select * from filetrack where fhash = \'" + hash +"\'")
	for row in outcome:
		if (hash == row[0]):
			return True
		else:
			return False

add_lock = threading.Lock()
def add(filehash): #add new file with status "inline"
	add_lock.acquire()
	try:
		status = "inline"
		if (inlist(filehash) == None):
			conn.execute("insert into filetrack (fhash, status) values (?,?)", (filehash,status))
			conn.commit()
		else:
			print filehash + " is already in the list"
	finally:
		add_lock.release()

update_lock = threading.Lock()
def status_update(hash,status): #change the status
	update_lock.acquire()
	try:
        	conn.execute("update filetrack set status = \'"+status+"\' where fhash = \'"+hash+"\'")
		conn.commit()
	finally:
		update_lock.release()

def next(): #next file to be processed
	outcome = conn.execute("select fhash from filetrack where status = \'inline\' limit 1")
	for row in outcome:
		return row[0]

setup_db()

