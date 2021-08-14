#!/usr/bin/python3
import re
from pwn import *
from astropy import units
from astropy.time import Time
from poliastro.bodies import Earth
from poliastro.twobody import Orbit

io = remote('192.168.1.38', 54321)

######## GET CHALLENGE STATE VECTOR ########
io.recvuntil(b'Pos (km):   [')
position = [float(i) for i in io.recvuntil(b']')[:-1].decode('ascii').split(', ')]

io.recvuntil(b'Vel (km/s): [')
velocity = [float(i) for i in io.recvuntil(b']')[:-1].decode('ascii').split(', ')]

io.recvuntil(b'Time:       ')
time = io.recvuntil(b'.000').decode('ascii')
time = Time(f"{time[:10]}T{time[11:]}") #correct format

print(f'Got challenge state vector:\n\
Position: {position}\n\
Velocity: {velocity}\n\
Time:     {time}\n')

######## RESOLVE ORBIT'S KEPLERIAN ELEMENTS ########
orbit = Orbit.from_vectors(Earth,
        position * units.km,
        velocity * units.km / units.s,
        epoch=time)

e = orbit.ecc                   #eccentricity
a = orbit.a                     #semi-major axis
i = orbit.inc.to(units.deg)     #inclination
o = orbit.raan.to(units.deg)    #longitude ascending node
w = orbit.argp.to(units.deg)    #argument of perigee
f = orbit.nu.to(units.deg)      #true anomaly

print(f'Resolved keplerian elements:\n\
Eccentricity:  {e}\n\
Semi-Major:    {a}\n\
Inclination:   {i}\n\
Longitude Asc: {o}\n\
Arg Perigee:   {w}\n\
True Anomaly:  {f}\n')

######## SUBMIT SOLVE ########

print("Solving...")
io.recvuntil(b'a (km): ')
io.sendline(bytes(str(a).split(' ')[0],'ascii'))

io.recvuntil(b'e: ')
io.sendline(bytes(str(e),'ascii'))

io.recvuntil(b'i (deg): ')
io.sendline(bytes(str(i).split(' ')[0],'ascii'))

io.recvuntil(b'\xce\xa9 (deg): ')
io.sendline(bytes(str(o).split(' ')[0],'ascii'))

io.recvuntil(b'\xcf\x89 (deg): ')
io.sendline(bytes(str(w).split(' ')[0],'ascii'))

io.recvuntil(b'\xcf\x85 (deg): ')
io.sendline(bytes(str(f).split(' ')[0],'ascii'))

io.recvuntil(b'flag:\n')
print(io.recv().decode('ascii'))
