#Imports
import RPi.GPIO as GPIO
import time
import pygame

#Setup
GPIO.cleanup()
GPIO.setmode(GPIO.BOARD)

bomb = 35
GPIO.setup(bomb, GPIO.OUT)

white_wire = 36
red_wire = 38
black_wire = 40

pin1 = red_wire
pin2 = black_wire
pin3 = white_wire

GPIO.setup(pin1,GPIO.IN,pull_up_down=GPIO.PUD_UP)
GPIO.setup(pin2,GPIO.IN,pull_up_down=GPIO.PUD_UP)
GPIO.setup(pin3,GPIO.IN,pull_up_down=GPIO.PUD_UP)

print "pin status: %s, %s, %s"%(GPIO.input(pin1),GPIO.input(pin2),GPIO.input(pin3))

def playsound(file):
    pygame.mixer.init()
    pygame.mixer.music.load(file)
    pygame.mixer.music.play()
    while pygame.mixer.music.get_busy() == True:
        continue

#clean exit
def clean_exit():
    print "Clean exit"
    GPIO.cleanup()
    quit()

#code for explosion
def explode():
    print "Exploded"
    playsound("/home/pi/exploded.mp3")
    GPIO.output(bomb,GPIO.HIGH) #Turn On
    time.sleep(30)
    GPIO.output(bomb,GPIO.LOW)
    clean_exit()

#win code:
def win():
    print "Defused"
    GPIO.output(bomb,GPIO.HIGH) #Turn On
    time.sleep(.1)
    GPIO.output(bomb,GPIO.LOW)
    time.sleep(.1)
    GPIO.output(bomb,GPIO.HIGH) #Turn On
    time.sleep(.1)
    GPIO.output(bomb,GPIO.LOW)
    playsound("/home/pi/defused.mp3")
    clean_exit()


#check for cuts
def checkpins():
    if GPIO.input(pin1) == 1:
        print "Pin1 disconnected"
        explode()
    if GPIO.input(pin2) == 1:
        print "Pin2 disconnected"
        win()
    if GPIO.input(pin3) == 1:
        print "Pin3 disconnected"
        explode()

def timer(minutes):
    seconds = minutes * 60
    start = time.time()
    time.clock()
    elapsed = 0
    while elapsed < seconds:
        checkpins()
        elapsed = time.time() - start

def start():
    print "planted"
    GPIO.output(bomb,GPIO.HIGH) #Turn On
    time.sleep(.1)
    GPIO.output(bomb,GPIO.LOW)
    time.sleep(.1)
    GPIO.output(bomb,GPIO.HIGH) #Turn On
    time.sleep(.1)
    GPIO.output(bomb,GPIO.LOW)
    playsound("/home/pi/planted.mp3")

start()
timer(50) #start timer for X minutes
print "Time's up"
explode() #timer ended without defuse? explode
