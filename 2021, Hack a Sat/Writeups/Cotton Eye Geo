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
b"\n 42173.94944457969 0.0009194705701843296 0.4294181891446367 123.86542988272755 295.3720590693332 75.78183988208784 2021-06-26 23:59:45.000001+00:00\n\nYou got it! Here's your flag:\nflag{sierra347984whiskey2:GC6iAHayTNLVVaFmuZtfi4KvXWSrBePvX9Yv-sl0VY5csbQa3Q4dVz7a_ws7NLuRIGs8I9Z9oP7VHwIPVbGBFwc}\n"
```
## Steps to Solve
1. Calculate current orbit, apoapse/periapse
2. Determine our transfer window (+/- 10km of target altitude)
3. Calculate burn to put SV on the correct orbital plane

## Our Solution
```
#!/usr/bin/python3
from pwn import *

x=-0.9091  #1.0302 #4      1
y=-1.0836       #0.8343 #2      1x=1.0302
z=0.02   #3.053  #1.071  3.059

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
    #42164

    #2021-06-26-19:20:00.000001-UTC


#2021-06-26-23:59:45.000001-UTC
run(26,23,59,45)
```
