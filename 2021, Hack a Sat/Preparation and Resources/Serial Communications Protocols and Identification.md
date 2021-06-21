# Common Serial Communications Bus Protocols/Architectures
Other well-known protocols not mentioned: USB, FireWire, Ethernet, Fibre Channel, MIDI, Serial Attached SCSI, Serial ATA, PCI Express, etc.
```
Last year, April, Erwin and I worked on a problem called 'Magic bus,' which took us almost 20 hours to finish because we were effectively doing blackbox reversing of raw bits. After they released the problem we found out it was a simulated I2C bus and that the protocol is well defined.

Problem:https://github.com/deptofdefense/HAS-Qualifier-Challenges/tree/master/bus
Intended Solution: https://github.com/deptofdefense/HAS-Qualifier-Challenges/blob/master/bus/solver/solve.py
``` 

This post will be about I2C and other bus/protocol architectures that may get used in competition, with the express goal of reducing the amount of potential blackbox reversing we will need to do this year. Some of these have python harnesses available, but we can write our own ones that will probably be more flexible with implementations of PySerial and some reading... hardware notwithstanding.

## I2C ("Inter IC”. Sometimes also called IIC or I²C bus)
### Overview
The Inter-Integrated Circuit (I2C) Protocol is a protocol intended to allow multiple "peripheral" digital integrated circuits ("chips") to communicate with one or more "controller" chips. Like the Serial Peripheral Interface (SPI), it is only intended for short distance communications within a single device. Like Asynchronous Serial Interfaces (such as RS-232 or UARTs), it only requires two signal wires to exchange information.

### Papers/Docs/Reading:
- What is it, official documentation... actually fairly english: https://www.i2c-bus.org/
- TI Paper on the EE fundamentals: https://www.ti.com/lit/an/slva704/slva704.pdf?ts=1624204437299
- Good readable overview of how it works: https://learn.sparkfun.com/tutorials/i2c/all

### Identifiers (from the competition):
```
10-bit addressing can be used together with 7-bit addressing since a special 7-bit address (1111 0XX) is used to signal 10-bit I2C address. When a master wants to address a slave device using 10-bit addressing, it generates a start condition, then it sends 5 bits signaling 10-bit addressing (1111 0), followed by the first two bits of the I2C address and then the standard read/write bit. There will always be a start and stop indicator, as well as a status acknowledgement
```

## RS232 (Recommended Standard 232)
### Overview
RS-232, is a standard originally introduced in 1960 for serial communication transmission of data. It formally defines signals connecting between a DTE (data terminal equipment) such as a computer terminal and a DCE (data circuit-terminating equipment or data communication equipment), such as a modem. The standard defines the electrical characteristics and timing of signals, the meaning of signals, and the physical size and pinout of connectors.

### Papers/Docs/Reading:
- Good overview, some frame discussion: https://learn.sparkfun.com/tutorials/serial-communication/all
- Frame ID, bitstream breakdown and layout: http://www.ece.northwestern.edu/local-apps/matlabhelp/techdoc/matlab_external/ch_seri8.html
- An example RS232 harnessing that uses PySerial: https://github.com/PyramidTechnologies/Python-RS-232

### Identifier:
```
The serial data format includes one start bit, between five and eight data bits, and one stop bit. A parity bit and an additional stop bit might be included in the format as well. The diagram below illustrates the serial data format.
```

## RS-485 (Recommended Standard 485)
### Overview
Also known as TIA-485(-A) or EIA-485, is a standard defining the electrical characteristics of drivers and receivers for use in serial communications systems. RS-485 supports inexpensive local networks and multidrop communications links, using the same differential signaling over twisted pair as RS-422. It is generally accepted that RS-485 can be used with data rates up to 10 Mbit/s[a] or, at lower speeds, distances up to 1,200 m (4,000 ft).[2] 

### Papers/Docs/Reading
- Broad overview and comparison to other RS protocols: https://www.maximintegrated.com/en/design/technical-documents/app-notes/3/3884.html
- Protocol breakdown, explains each layer like the OSI model: https://www.cuidevices.com/blog/rs-485-serial-interface-explained
- Comparison between RS232 and RS485: https://www.evaluationengineering.com/applications/communications-test/article/21137222/whats-the-difference-between-the-rs232-and-rs485-serial-interfaces

### Identifier
```
UART generally has a normal format that most devices will use, but many options can be configured to change the norm. The idle state of UART is voltage high, so to begin transmission the UART uses a low pulse called a start bit, followed by 8 bits of data, and is completed with a high stop bit, this may vary... didn't spend a ton of time finding protocol specs
```

## SPI
### Overview
I sort of doubt this will be in use because it requires four isolated data lines, but regardless here it is. Serial Peripheral Interface (SPI) is an interface bus commonly used to send data between microcontrollers and small peripherals such as shift registers, sensors, and SD cards. It uses separate clock and data lines, along with a select line to choose the device you wish to talk to. 

### Papers/Docs/Reading:
- Raspi docs for SPI, but lots of good diagrams and explanation: https://raspberrypi-aa.github.io/session3/spi.html
- Protocol Description and Python Implementation: http://onioniot.github.io/wiki/Documentation/Libraries/SPI-Python-Module.html

### Identifier
```
See the first link for diagrams
```

## 1-Wire
### Overview
1-Wire is a device communications bus system designed by Dallas Semiconductor Corp. that provides low-speed (16.3 kbit/s[1]) data, signaling, and power over a single conductor. 1-Wire is similar in concept to I²C, but with lower data rates and longer range. It is typically used to communicate with small inexpensive devices such as digital thermometers and weather instruments. A network of 1-Wire devices with an associated master device is called a MicroLAN. 

### Papers/Docs/Reading
- How to communicate, ie: data format: https://www.maximintegrated.com/en/design/technical-documents/app-notes/1/126.html
- Sampling information: https://scienceprog.com/understanding-1-wire-interface/
- Technical protocol doc: https://www.maximintegrated.com/en/design/technical-documents/tutorials/1/1796.html

### Identifier
```
Hopefully they dont do this to us because I think this will be really hard to reverse:

The four basic operations of a 1-Wire bus are Reset, Write 1 bit, Write 0 bit, and Read bit. The time it takes to perform one bit of communication is called a time slot in the device data sheets. Byte functions can then be derived from multiple calls to the bit operations. Its basically an unformatted bitstream
```
