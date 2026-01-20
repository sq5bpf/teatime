# TEAtime v0.1 TEA1 short key recovery 

Jacek Lipkowski <sq5bpf@lipkowski.org>

This is a very simple/naiive TEA1 short key recovery implementation.

Assume that the first 32 bits for some type2 frame are the same if 
they belong to the same address.
So if we have two frames for the same address then we can find a
short TEA1 key for which:

keystream1 xor (first 32 bits of frame1) == keystream2 xor (first 32 bits of frame2)


But to save time, i do a simple trick (equivalent to the above but faster): 

pre-calculate x=(first 32 bits of frame1) xor (first 32 bits of frame2)

find a short key for which (keystream1 xor keystream2) == x

Note: this is very naiive, and could be sped up by orders of
magnitude. Whole keyspace search takes about 2h on an old laptop cpu
(Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, stepping 12). The MidnightBlue
team's demo on a vintage 2000's laptop with only a single core took 8h, so clearly 
it can be made much faster.


The TEA1 part contains mostly crypto/tea1.c authored by Wouter Bokslag from 
MidnightBlue,  and also random other stuff
copy-pasted from osmo-tetra, so the license is same as the tea1.c file: AGPL-3.0.


Example keys taken from https://github.com/hassanTripleA/tea_crack_CT/. 
This software has since disappeared from github. 
And also it required an nvidia gpu (which i didn't have) and i could not get it to work.

## Compiling

This software was tested on Debian 12 GNU/Linux. 
It should run on any system which has the pthread library avaliable.

To compile just type: make


## Command line parameters

### Crack mode:

````
./teatime c hn1 mn1 fn1 tn1 ud1 ct1 hn2 mn2 fn2 tn2 ud2 ct2  - crack mode, takes data from two frames, calculates 32bit key and keystream xor cipertext
hn - hyperframe number
mn - multiframe number
tn - frame number
ud - 0 - downlink, 1 uplink
ct - first 32 bits of ciphertext as hex
short_key - 32 bit TEA1 short key as hex
````

Example test vector:
````
./teatime c 110 30 6 1 0 151ef027 110 30 7 1 0 4d00159e - crack and get key 00000111
````

In crack mode the software will use all CPUs it can find. To change this please set the NPROC environment variable.

During cracking each thread prints the time to search all of the keyspace and speed in keys/second.

### Verify mode:
````
./teatime v hn1 mn1 fn1 tn1 ud1 ct1 short_key                - verify mode, takes data from one frame and 32bit key, shows keystream xor cipertext
````

Example test vectors:
````
./teatime v 110 30 6 1 0 151ef027 00000111
./teatime v 110 30 7 1 0 4d00159e 00000111
````
If the key is correct and both frames have the same data in their first 32 bits of plaintext, then this should result in the same
ciphertext^keystream value.


## Obtaining input data

One possible source of data is running a patched osmo-tetra on your own network which runs TEA1.
Use the version from here:
https://github.com/sq5bpf/osmo-tetra-sq5bpf-2

./tetra-rx -r -s tetra_bits.bin > tetra_rx_stdout 2> tetra_rx_stderr

Search tetra_rx_stdout for the string "key recovery candidate" and the same Addr field, same cckid, and only one entry per burst.

Examples:
````
SQ5BPF: (110/30/6) len:103 cckid:0 key recovery candidate: [110 30 6 1 0 151ef027] Addr: [SSI + Usage Marker(1234/U42)]
SQ5BPF: (110/30/7) len:103 cckid:0 key recovery candidate: [110 30 7 1 0 4d00159e] Addr: [SSI + Usage Marker(1234/U42)]
````

Give data from two frames to teatime:
````
./teatime c 110 30 6 1 0 151ef027 110 30 7 1 0 4d00159e
````

This will result in a probable key 00000111 being found.

Test this key for a few more frames:
````
./teatime v 110 30 6 1 0 151ef027 00000111
./teatime v 110 30 7 1 0 4d00159e 00000111
./teatime v 110 30 8 1 0 b0dfc76c 00000111
````

If the key is correct, then keystream xor ciphertext should be the same.


## FAQ

### Tell me more about TETRA encryption

There are many TEAx encryption algorithms, with varying strength.

TEA1 - for everyone, 
TEA2 - for goverment in Schengen area, 
TEA3 - for goverments outside the Schengen area
TEA4 - for everyone (this is an upgrade to TEA1),


TEA1 is the weakest of them all, and ETSI has suggested that TEA4 is a replacement.

These algorithms have not been documented, however they were reverse engineered by the
MidnightBlue team, and published in 2023: https://www.midnightblue.nl/research/tetraburst

All of these algorithms use a 80bit key.

Since the weaknessed have been disclosed three more algorithms have been released: TEA5, TEA6 and TEA7



### What is the problem with TEA1?

From the excellent Midnight Blue research we know the TEA1 encryption uses a 32-bit key,
which is derived from the (known) network parameters and the 80-bit key.

This 32-bit key can be bruteforced (for example using this software).

This key weakening function can be considered a deliberate backdoor which enables eavesdropping
by the services which influenced development of these algorithms.


### Is this still relevant?

No, in 2026 it shouldn't be. The TEA1 algorithm has been known to be the weakest, with ETSI providing an alternative (TEA4).

After the MidnightBlue publications we now know the deails (the key shortening function).

Since this was published in 2023, all entities had adequate time to migrate.

In short: anyone still using TEA1 is either an idiot, or has done a very extensive risk analysis
(and for some reason it has shown tat the risk canbe accepted).


### What about goverment services?

Goverment entities should be using the encryption algorithms which have been 
specifically developed for them. TEA2 in the Schengen area or TEA3 outside of the Schengen area.

So their traffic was secure before the publications in 2023 and still is.

Also these goverment entities should have included Kerckhoffs's principle in their risk analysis.
These are proprietary algorithms, so they were not subject to peer review and thus may
contain vulnerabilities either because of error (and no peer review) or delibrerate
weakening (which can't be discovered by peer review). 

And in this case this has prooven to be true (and in other cases like for example GSM A5/1).


### How do i use this key?

You can use an experimental telive version from here:
https://github.com/sq5bpf/telive-2
Which uses this version of osmo-tetra:
https://github.com/sq5bpf/osmo-tetra-sq5bpf-2


### So how do i know a network uses TEA1?

There is no easy way to know. If you find the key, and the traffic decodes correctly then it's TEA1.


### How can i test?

Either use your own network or get permission. Set TEA1 or ask the owner to set TEA1.

Listen with osmo-tetra-sq5bpf-2 to get candidates for key recovery.

Plug them into teatime, obtain the short 32 bit key

Make a keyfile for osmo-tetra-sq5bpf-2 using this key

Set osmo-tetra-sq5bpf-2 to use this keyfile, and preferably use telive-2 to listen to the voice traffic.

Ask the owner to send some voice traffic, see it it is decoded correctly.


### It's five o clock

teatime!

