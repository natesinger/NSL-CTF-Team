#!/usr/bin/python3
from pwn import *
from numpy.linalg import norm
from astropy import units
from astropy.time import Time, TimeDelta
from astropy.units.quantity import Quantity
from poliastro.bodies import Earth
from poliastro.twobody import Orbit

io = remote('192.168.1.37', 54321)
TARGET_ICRF_RADIUS = 42164


######## GET STARTING ORBIT FROM STATE VECTOR ########
io.recvuntil(b'Pos (km):   [')
position = [float(i) for i in io.recvuntil(b']')[:-1].decode('ascii').split(', ')]

io.recvuntil(b'Vel (km/s): [')
velocity = [float(i) for i in io.recvuntil(b']')[:-1].decode('ascii').split(', ')]

io.recvuntil(b'Time:       ')
time = io.recvuntil(b'.000').decode('ascii')
time = Time(f"{time[:10]}T{time[11:]}") #correct format

transfer_orbit = Orbit.from_vectors(Earth,
        position * units.km,
        velocity * units.km / units.s,
        epoch=time)

print(f'Got challenge state vector:\n\
  Position: {transfer_orbit.r}\n\
  Velocity: {transfer_orbit.v}\n\
  Time:     {transfer_orbit.epoch}\n\
  R(ICRF):  {norm(transfer_orbit.r.value)}\n')


######## PROPAGATE FORWARD IN ORBITAL PERIOD UNTIL R=a=42164 ########
print(f'Finding first valid burn opportunity ({TARGET_ICRF_RADIUS} km)...')

while norm(transfer_orbit.r.value) < TARGET_ICRF_RADIUS:
    transfer_orbit = transfer_orbit.propagate(
        transfer_orbit.epoch + TimeDelta(1, format='sec'))
    print(f'\r  {transfer_orbit.epoch} r:{norm(transfer_orbit.r.value)} km ', end='')

print(f'\r\
  Position: {transfer_orbit.r}\n\
  Velocity: {transfer_orbit.v}\n\
  Time:     {transfer_orbit.epoch}\n\
  R(ICRF):  {norm(transfer_orbit.r.value)}\n')


######## CALCULATE DV REQUIRED TO CIRCULARIZE ########
final_orbit = Orbit.from_classical(Earth,
        Quantity(TARGET_ICRF_RADIUS, unit="km"),
        Quantity(0.0), #eccentricity
        Quantity(0.0, unit="rad"), #inclindation
        transfer_orbit.raan,
        transfer_orbit.argp,
        transfer_orbit.nu,
        epoch=transfer_orbit.epoch)

print(f'Velocities at {final_orbit.epoch}:\n\
  Transfer: {transfer_orbit.v}\n\
  Final:    {final_orbit.v}\n')

solution_time = str(final_orbit.epoch).replace('T','-')+"-UTC"
solution_Dv = (final_orbit.v - transfer_orbit.v)

######## HARNESS SOLUTION ########

print(f'Final Solution:\n\
  Time: {solution_time}\n\
  Dv_x: {solution_Dv.value[0]}\n\
  Dv_y: {solution_Dv.value[1]}\n\
  Dv_z: {solution_Dv.value[2]}\n')

io.recvuntil(b'Time: ')
io.sendline(f'{solution_time}'.encode('ascii'))

for i in range(3):
    io.recvuntil(b'(km/s): ')
    io.sendline(f'{solution_Dv.value[i]}'.encode('ascii'))

io.recvuntil(b'flag:\n')
print(io.recv().decode())
