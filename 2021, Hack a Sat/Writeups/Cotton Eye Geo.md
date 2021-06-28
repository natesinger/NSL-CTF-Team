# Hack a Sat 2021, Writeup: Cotton Eye Geo
## Problem Overview
### Hint: 
(not really a hit) Where do you go?
### On connect:
```
singern@ubuntu:~/Desktop/HAS-2021/cotton-eye-geo$ ./run.py 
[+] Opening connection to visual-sun.satellitesabove.me on port 5014: Done
2021-06-26-23:59:45.000001-UTC
[*] Closed connection to visual-sun.satellitesabove.me port 5014
Time: 2021-06-26-23:59:45.000001-UTC
Altitude: 42164.39157587264

<here we can send a delta-v vector of 0,0,0 at a time and we get back the Keplerian parameters>
```
### Goal
We are given our keplerian parameters for any point in time we provide. The goal is to specify a delta-v vector at a point in time in order to put the SV in equitorial orbit with specific constraits like the eccentricity must be <0.001 and semi-major axis must be +/- 10km.

## Steps to Solve
1. Brute force the orbital parameters--by checking altitude at time we can find the apoapsis, periapsis, orbital period
    a. This is done using the formula in our solution finding altitude from true anomaly
2. Find a point in the orbital period that we can use for our transfer, altitude = 42164 +/-10km, this is our time to execute
    a. We tested points by brute force and found we could use 2021-06-26-29:23:25.000001-UTC for the transfer time
    b. Its important to get as close as we can here, but as high in the orbital period so we get leverage on the maneuver
    c. There are ultimately two options, the point in time where we are 42164km prograde to the apoapsis or 42164km altitude as we move retrograde
3. We chose the point in prograde and at that time we must rotate the orbit to the left of our reference frame to move the periapsis to the other side of the earth and then reduce the semi-major axis to make it eccentric. You can caulcate these two values if you know the keplerian points that you want at that point, but you can also brute force the values fairly easily as its obviously minor x and y orientation changes given that you are at is roughly equitorial. There is also a point in the orbit where the SV is at the approperiate height, and therefor this can be done in a single burn. Finally, we dont need to do any time averaging because we are able to provide a delta-v vector that gets applied instantly.

## Our Solution
```
#!/usr/bin/python3
from pwn import *

def run(day:int, hours:int, mins:int, sec:int):
    io = remote('visual-sun.satellitesabove.me', 5014)
    time = f'2021-06-{day:02d}-{hours:02d}:{mins:02d}:{sec:02d}.000001-UTC'
    print(time)
    io.sendafter('Ticket please:\n', 'ticket{sierra347984whiskey2:GCgrrwDVh3EEgyJV014cInJjwQrQvUHHXEkGNQygy92Z3HSjNpUpld0ZMzttwQmN_g}\n', timeout=3)
    io.recv()
    io.sendline(time)
    io.recv()
    io.sendline(str(x))
    io.recv()
    io.sendline(str(y))
    io.recv()
    io.sendline(str(z))
    io.recvuntil('New Orbit (a, e, i, Ω, ω, υ, t):')
    result = io.recv()
    results = [result.split()[i] for i in range(6)]

    a = float(results[0].decode('UTF-8')) #semi major axis
    e = float(results[1].decode('UTF-8')) #eccentricity
    i = float(results[2].decode('UTF-8')) #inclination
    o = float(results[3].decode('UTF-8')) #longitude of the center node
    w = float(results[4].decode('UTF-8')) #argument of perapsis
    u = float(results[5].decode('UTF-8')) #true anomaly

    #radius from true anomaly
    altitude = a * ((1 - (e*e)) / (1 + (e * math.cos(math.radians(u)))))
    io.close()

    print(f'Time: {time}')
    print(f'Altitude: {altitude}')
    print(result)

    return altitude

x=-0.9091
y=-1.0836
z=0.02

run(26,23,59,45)
```
