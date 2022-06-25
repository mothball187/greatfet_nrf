# greatfet_nrf
`greatrfet_nrf` is a Python library used to control an nRF24 chip with [GreatFET](https://greatscottgadgets.com/greatfet/). The library supports using the nRF to perform promiscuous sniffing via the method discovered by Travis Goodspeed and shared in his blog post [here](http://travisgoodspeed.blogspot.com/2011/02/promiscuity-is-nrf24l01s-duty.html)

A lot of the code in this library was ported from or influenced by the [goodfet](https://github.com/travisgoodspeed/goodfet) and the [RadioHead NRF24](https://www.airspayce.com/mikem/arduino/RadioHead/classRH__NRF24.html) projects.

Check out `init_radio`, `autotune`, `find_channel`, and `record_packets` for quick ways to interface with this library.
