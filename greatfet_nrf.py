import time
import greatfet
import sys
import binascii

R_REGISTER=          0x00
W_REGISTER=          0x20
REGISTER_MASK=       0x1F
ACTIVATE=            0x50
R_RX_PL_WID=         0x60
R_RX_PAYLOAD=        0x61
W_TX_PAYLOAD=        0xA0
W_TX_PAYLOAD_NOACK=  0xB0
W_ACK_PAYLOAD=       0xA8
FLUSH_TX=            0xE1
FLUSH_RX=            0xE2
REUSE_TX_PL=         0xE3
RF24_NOP=            0xFF

REG_CONFIG=               0x00
REG_EN_AA=                0x01 # Shockburst
REG_EN_RXADDR=            0x02
REG_SETUP_AW=             0x03
REG_DYNPD=                0x1C
REG_FEATURE=              0x1D
REG_RF_SETUP=             0x06
REG_STATUS=               0x07
REG_RX_ADDR_P0=           0x0A
REG_RF_CH=                0x05
REG_TX_ADDR=              0x10

RX_PW_P0=                 0x11
TX_DS=                    0x20
MAX_RT=                   0x10


CE_PIN = "J1_P17"
LOGITECH_PRES_CHANS = [5, 8, 14, 17, 32, 35, 41, 44, 62, 65, 71, 74]
LOGITECH_MOUSE_ADDR = b"\x07\x02\x97\x50\x5A" # 0x5A50970207
LOGITECH_PRES_DONGLE_ADDR  = b"\x00\x8F\x97\xB0\xBA" # 0xBAB0978F00
LOGITECH_PRES_ADDR  = b"\x07\x8F\x97\xB0\xBA" # 0xBAB0978F07
LOGITECH_PRES_PAIR_PL = [0x07, 0x51, 0x07, 0x05, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99]

class GreatFETNRF():
    def __init__(self, gf):
        self.gf = gf
        self.ce_pin = self.gf.gpio.get_pin(CE_PIN)
        self.ce_pin.set_direction(self.gf.gpio.DIRECTION_OUT)
        self.ce_pin.write(False)
        
    def flush_rx(self):
        status = self.gf.spi.transmit([FLUSH_RX])
        return ord(status)
        
    def flush_tx(self):
        status = self.gf.spi.transmit([FLUSH_TX])
        return ord(status)

    def reg_write(self, reg, value):
        status = self.gf.spi.transmit( [W_REGISTER | (REGISTER_MASK & reg), value] )
        return status[0]
        
    def reg_write_buf(self, reg, buf):
        if type(buf) is not list:
            buf = list(buf)
            
        status = self.gf.spi.transmit( [W_REGISTER | (REGISTER_MASK & reg)] + buf )
        return status[0]
        
    def reg_read(self, reg, size=1):
        buf = self.gf.spi.transmit( [R_REGISTER | (REGISTER_MASK & reg )], receive_length=size+1 )
        return int.from_bytes(buf[1:], 'little')
        
    def get_maclen(self):
        """Get the number of bytes in the MAC address."""
        choices = [2, 3, 4, 5]
        choice = self.reg_read(REG_SETUP_AW) & 3
        self.maclen = choices[choice]
        return self.maclen
        
    def set_maclen(self, maclen):
        choices=["illegal", "illegal",
                 0,       #undocumented 
                 1, 2, 3  #documented
                 ]
        choice=choices[maclen]
        self.reg_write(REG_SETUP_AW, choice)
        self.maclen=maclen
    
    def tune(self,tuning="aa,c78c65805e,14,09"):
        """Tune the radio."""
        #MAC,rA,r5,r6
        fields = tuning.split(",")
        ra, ra2 = int(fields[1],16).split("|")
        r5 = int(fields[2],16)
        r6 = int(fields[3],16)
        self.reg_write(REG_RX_ADDR_P0,ra)
        self.reg_write(REG_RF_CH,r5)
        self.reg_write(REG_RF_SETUP,r6)
        self.set_maclen(3)
    
    def status(self):
        """Read the status byte."""
        status = ord(self.gf.spi.transmit( [R_REGISTER | (REGISTER_MASK & REG_STATUS )], receive_length=1 ))
        # print("Status=%02x" % status)
        return status
    
    def get_rate(self):
        rate = self.reg_read(REG_RF_SETUP) & 0x28
        if rate == 0x20:
            rate = 250 * 10 ** 3 #256kbps
        elif rate == 0x08:
            rate = 2 * 10 ** 6  #2Mbps
        elif rate == 0x00: 
            rate = 1 * 10 ** 6  #1Mbps
        return rate
        
    def set_rate(self, rate= 2 * 10 ** 6):
        r6 = self.reg_read(REG_RF_SETUP) #RF_SETUP register
        r6 = r6 & (~0x28)  #Clear rate fields.
        if rate == 2 * 10 ** 6:
            r6 = r6 | 0x08
        elif rate == 1 * 10 ** 6:
            r6 = r6
        elif rate == 250 * 10 ** 3:
            r6 = r6 | 0x20
        print("Setting r6=%02x." % r6)
        self.reg_write(REG_RF_SETUP, r6) #Write new rate.
        
    def set_freq(self, frequency):
        """Set the frequency in Hz."""
        
        #On the NRF24L01+, register 0x05 is the offset in
        #MHz above 2400.
        
        chan = frequency / 1000000 - 2400
        self.reg_write(REG_RF_CH, chan)


    def get_freq(self):
        """Get the frequency in Hz."""
        
        #On the NRF24L01+, register 0x05 is the offset in
        #MHz above 2400.
        
        return (2400 + self.reg_read(REG_RF_CH)) * 10 ** 6
        
    def get_src_mac(self):
        """Return the source MAC address."""
        
        mac = self.reg_read(REG_RX_ADDR_P0, size=5)
        return mac
        
    def set_src_mac(self,mac):
        """Set the source MAC address."""
        self.reg_write_buf(REG_RX_ADDR_P0, [0, 0, 0, 0, 0])
        self.reg_write_buf(REG_RX_ADDR_P0, mac)
        
    def get_dst_mac(self):
        """Return the target MAC address."""
        
        mac = self.reg_read(REG_TX_ADDR, size=5)
        return mac
        
    def set_dst_mac(self, mac):
        """Set the target MAC address."""
        self.reg_write_buf(REG_TX_ADDR, [0, 0, 0, 0, 0])
        self.reg_write_buf(REG_TX_ADDR, mac)

    def rxpacket(self, full=False, printing=False):
        """Get a packet from the radio.  Returns None if none is waiting."""
        status = self.status()

        if status & 0x40:
            # self.ce_pin.write(False)
            # Get the packet
            if full:
                size = self.get_packetlen()
            else:
                size = self.gf.spi.transmit([R_RX_PL_WID], receive_length=2)
                size = size[1]
            data = self.gf.spi.transmit([R_RX_PAYLOAD], receive_length=size+1)
            self.reg_write(REG_STATUS, 0x40) #clear bit.
            if printing:
                print(binascii.hexlify(data[1:]))

            return data[1:]
            
        elif self.status() == 0:
            self.flush_rx()
            self.reg_write(REG_STATUS, 0x40) #clear bit.
            
        return None
        
    def txpacket(self,payload):
        if type(payload) is not list:
            payload = list(payload)

        self.gf.spi.transmit([W_TX_PAYLOAD_NOACK] + payload)
        # self.gf.spi.transmit([W_TX_PAYLOAD] + payload)
        self.set_tx_mode()
        status = 0
        while not (status & (TX_DS | MAX_RT)):
            status = self.status()

        if status & MAX_RT:
            self.flush_tx()

        self.set_idle()
        self.reg_write(REG_STATUS, TX_DS | MAX_RT)
        return status & TX_DS

    def carrier(self):
        """Hold a carrier wave on the present frequency."""
        # Set CONT_WAVE, PLL_LOCK, and 0dBm in RF_SETUP            
        self.reg_write(REG_RF_SETUP, 8+10+4+2); 
    
    def set_packetlen(self,len=16):
        """Set the number of bytes in the expected payload."""
        self.reg_write(RX_PW_P0,len)
        self.packetlen = len
        
    def get_packetlen(self):
        """read the number of bytes in the expected payload."""
        len = self.reg_read(RX_PW_P0)
        self.packetlen = len
        return len
        
    def power_up(self):
        cfg = self.reg_read(REG_CONFIG)
        cfg = cfg | 2
        cfg = self.reg_write(REG_CONFIG, cfg)
        time.sleep(5) 
        
    def init_autotune(self, altrate=True, chan=True, threshold=5, altsync=True, macreject=True, printing=False, tgt_maclen=5):
        self.altrate=altrate
        self.chan=chan
        self.altsync=altsync
        self.macreject = macreject
        self.printing = printing
        self.tgt_maclen = tgt_maclen
        self.tunecount = 0
        self.threshold = threshold
        self.addresses = {}
        
        self.reg_write(REG_CONFIG, 0x00) #Stop nRF
        self.set_idle()
        self.reg_write(REG_STATUS, 0x1c) # clear interrupts
        self.reg_write(REG_DYNPD, 0x0) # disable shockburst
        self.reg_write(REG_EN_AA, 0x00) #Disable Shockburst
        self.reg_write(REG_FEATURE, 0x05) # or 0? disable payload-with-ack, enable noack
        # self.reg_write(REG_FEATURE, 0x06) # or 0? disable payload-with-ack, enable noack
        self.set_packetlen(32) #Longest length.
        self.set_maclen(2) # SETUP_AW for shortest
        self.set_src_mac((0x0055).to_bytes(2, 'little'))
        self.set_idle()
        self.flush_rx()
        self.flush_tx()
        self.reg_write(REG_RF_CH, self.channels[0])
        self.reg_write(REG_RF_SETUP,self.rate) #2MBps, -18dBm in RF_SETUP
        time.sleep(2)       
        
        # self.reg_write(REG_STATUS,0x78) #Reset status register
        # self.reg_write(REG_EN_RXADDR, 0x01) #Set RX Pipe 0

        # prime for RX, no checksum
        self.reg_write(REG_CONFIG,0x03) # PWR_UP, and PRIM_RX
        self.ce_pin.write(True)
        time.sleep(2)
        
    
    def set_idle(self):
        self.reg_write(REG_CONFIG, 0x0C) # enable 2-byte CRC
        # self.reg_write(REG_EN_RXADDR, 0x0)
        self.ce_pin.write(False)
        
    def set_rx_mode(self):
        self.reg_write(REG_CONFIG, 0x0F) # enable 2-byte CRC, PWR_UP, and PRIM_RX
        # self.reg_write(REG_EN_RXADDR, 0x03) #Set RX Pipe 0 and 1
        self.ce_pin.write(True)
        time.sleep(200 / 1000)

    def set_tx_mode(self):
        self.ce_pin.write(False)
        self.reg_write(REG_STATUS, 0x30)
        self.reg_write(REG_CONFIG, 0x0E) # enable 2-byte CRC, PWR_UP
        self.ce_pin.write(True)
        time.sleep(2 / 1000)
        
    def init_radio(self, rate=2, srcmac=b"\xe7\xe7\xe7\xe7\xe7", dstmac=b"\xe7\xe7\xe7\xe7\xe7", ch=16, disable_aa=False):
        self.reg_write(REG_CONFIG, 0x00) #Stop nRF
        self.set_idle()
        # self.reg_write(REG_EN_AA, 0x00) #Disable Shockburst
        # self.set_packetlen(32) #Longest length.
        # self.set_maclen(5)
        # self.set_src_mac(srcmac)
        
        if rate == 2:
            self.rate = 8
        else:
            self.rate = 0

        self.reg_write(REG_STATUS, 0x1c) # clear interrupts
        if disable_aa:
            self.reg_write(REG_EN_AA, 0x00) #Disable Shockburst

        self.reg_write(REG_DYNPD, 0x3F) # enable dynamic payload length on all pipes
        self.reg_write(REG_FEATURE, 0x05) # disable payload-with-ack, enable noack
        # self.reg_write(REG_FEATURE, 0x07) # disable payload-with-ack, enable noack
        self.set_idle()
        self.flush_rx()
        self.flush_tx()
        self.set_maclen(len(srcmac))
        self.set_src_mac(srcmac)
        self.set_dst_mac(dstmac)
        self.reg_write(REG_RF_CH, ch)
        self.reg_write(REG_RF_SETUP, self.rate) #2MBps, -18dBm in RF_SETUP
        time.sleep(2)
        
        
    def packetaddr(self,packet,justmac=False):
        """Returns a loaded packet address, including channel and rate."""
        
        sync = self.get_src_mac() & 0xFF
        
        mac=""
        #mac2=""
        #MAC,RF_CH,RATE
        #macmess = packet[1:self.tgt_maclen+2]
        macmess = packet[:self.tgt_maclen+1]
        # print("DEBUG: %s" % repr(macmess))
        bitmask = (1 << (self.tgt_maclen * 8)) - 1
        macbits = (int.from_bytes(macmess, 'big') >> 7) & bitmask
        for c in macbits.to_bytes(self.tgt_maclen, 'big'):
            mac = "%s%02x" % (mac,c)
        
        #for i in range(self.tgt_maclen):
        #    mac2 = "%s%02x" % (mac2,packet[i+1])
         
        #for i in range(self.tgt_maclen):
        #    mac = "%s%02x" % (mac,packet[i])
        
        if justmac:
           # return (mac, mac2)
            return (mac)
            
        ch = self.reg_read(REG_RF_CH)
        rate = self.reg_read(REG_RF_SETUP)
        
        #return "%02x,%s|%s,%02x,%02x" % (sync,mac,mac2,ch,rate)
        return "%02x,%s,%02x,%02x" % (sync,mac,ch,rate)
            
    def validmac(self,packet):
        # TODO: check this code
        sync = self.get_src_mac() & 0xFF
        mac = self.packetaddr(packet, justmac=True)
        
        #BT preamble is A or 5.
        #Fix this to work on the smallest bit, not the highest.
        
        if ((packet[0] & 0x80) ^ (sync & 0x80)) and self.macreject:
            #print "%02x%02x invalid entry." % (sync,packet[0]);
            #This is a special kind of failure.  Freq is probably right, but MAC is wrong.
            return False
            
        blacklist=['5555555555', 'aaaaaaaaaa',
                   '0000000000', 'ffffffffff',
                   '55555555',   'aaaaaaaa',
                   '00000000',   'ffffffff',
                   '555555',     'aaaaaa',
                   '000000',     'ffffff',
                   '7fffff', 'aaffff', 'aaaaff',
                   'afffff', 'abffff', '5fffff']
                   
        for foo in blacklist:
            if mac == foo:
                return False
                
        return True
        
    def printpacket(self, packet):
        s=""
        i=0
        for foo in packet:
            i = i + 1
            if i > self.get_packetlen(): break
            s = "%s %02x" % (s, foo)
        print("%s" % s)
    
    def handle(self,packet):
        """Handles a packet."""
        if self.printing:
            self.printpacket(packet)
        
        if not self.validmac(packet):
            #print "Dropped packet from %s" % self.packetaddr(packet,justmac=True);
            #self.printpacket(packet);
            return
        
        addr = self.packetaddr(packet)
        
        #Increment the address count.
        count=0
        try:
            count = self.addresses[addr]
        except:
            pass
            
        self.addresses[addr] = count + 1
        rate = count * 1.0 / len(self.addresses)
        if self.addresses[addr] >= self.threshold:
            print("'%s' looks valid\t%i\t%0.5f" % (addr,count,rate))
        return addr
    
    def selftune(self, forever=False, delay=5.0):
        """Tunes to the first strong signal.
        It's important that this not get triggered by false positives."""
        
        while 1:
            if len(self.addresses) > 0:
                print("continue sniffing? (y/n)")
                inp = input()
                if inp.lower() == "n":
                    break

            self.retune()
            start = time.mktime(time.localtime())
            sys.stdout.flush()
            while (time.mktime(time.localtime()) - start) < delay:
                packet = None
                start2 = time.mktime(time.localtime())
                while packet == None and (time.mktime(time.localtime()) - start2) < 1:
                    packet = self.rxpacket(full=True)
                    
                if packet is None:
                    pass
                else:
                    addr = self.handle(packet)
                    try:
                        count = self.addresses[addr]
                    except:
                        count = 0
                    
    def retune(self):
        """Tunes to another channel or preamble looking for the next packet."""
        count = self.tunecount
        self.tunecount = count + 1
        #Swap the SYNC value most often.
        if self.altsync:
            sync = 0x0055
            if count & 1:
                sync = 0x00AA
            self.set_src_mac(sync.to_bytes(2, 'little'))
            print("set src mac to %04X" % self.get_src_mac())
            count = (count >> 1)
        
        if self.altrate:
            #Then the data rate.
            rate = 0
            
            #This swaps between 1Mbps and 2Mbps.
            #TODO add support for 256kbps, if anyone uses it.
            if count & 1:
                rate = rate | 0x08
            
            if(rate == 0x20):
                rate = 0x08
                
            print("Setting rate to 0x%02x" % rate)
            self.reg_write(REG_RF_SETUP, rate)
            count = (count >> 1)
        
        if self.chan:
            self.reg_write(REG_RF_CH, self.channels[count % len(self.channels)])
            print("Tuned to %i MHz" % (self.get_freq() / (10 ** 6)))
            
        #Grab two packets to clear buffers.
        #Should retune only after a few packets to reduce this delay.
        packet=self.rxpacket()
        packet=self.rxpacket()

    def autotune(self, tgt_maclen=5, threshold=5, channels=None, altrate=True, rate=2, altsync=False, printing=False):
        # TODO: returning shifted bits for sniffed macs
        if channels is None:
            self.channels = list(range(1, 127))
        else:
            self.channels = channels
        
        if rate == 2:
            self.rate = 8
        else:
            self.rate = 0

        self.init_autotune(altrate=altrate,altsync=altsync,chan=True, threshold=threshold, printing=printing, tgt_maclen=tgt_maclen)
        print("Autotuning on %i MHz" % (self.get_freq() / 10 ** 6))
        print("sync,mac,r5,r6")
        #Now we're ready to get packets.
        self.selftune(delay=10, forever=True)
   
    def find_channel(self, srcmac, dstmac, channels, rate=2):
        self.init_radio(srcmac=srcmac, dstmac=dstmac, rate=rate)
        self.set_rx_mode()
        for ch in channels:
            self.reg_write(REG_RF_CH, ch)
            print("tuning to %i MHz" % (self.get_freq() / (10 ** 6)))
            pl_count = 0
            for i in range(25):
                # print("listening for packets..")
                
                # self.txpacket(pair_payload)
                pl = self.rxpacket(printing=True)
                if pl is not None:
                    pl_count += 1

                time.sleep(100 / 1000)

            print("%d payloads received on this channel" % pl_count)
            # print("%d payloads received on this channel, continue? (y/n)" % pl_count)
            # a = input()
            # if a.lower() == "y":
            #     continue

            # break

    def record_packets(seconds=30, delayms=100, filename=None):
        print("listening and recording for %d seconds" % seconds)
        seconds = float(seconds)
        start = time.mktime(time.localtime())
        if filename is not None:
            wp = open(filename, "w")
            
        while (time.mktime(time.localtime()) - start) < seconds:
            packet = self.rxpacket(printing=True)
            if filename is not None and packet is not None:
                wp.write("%f %s (%d bytes)" % (time.mktime(time.localtime()), binascii.hexlify(packet), len(packet)))
                
        wp.close()