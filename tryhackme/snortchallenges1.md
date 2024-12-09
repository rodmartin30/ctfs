# Snort Challenge - The Basics

Put your snort skills into practice and write snort rules to analyse live capture network traffic.

## Task 2

In this task we need to create IDS Rules for HTTP traffic.

##### Write a single rule to detect "all TCP port 80 traffic" packets in the given pcap file:

```
alert tcp any any <> any 80 (msg:"Incoming TCP traffict at port 80";sid:100001;rev:1;)
```

Run the snort with local rules and pcap file
```
sudo snort -c local.rules -A full -l . -r mx-3.pcap
```

##### What is the destination address of packet 63?

Approach (incorrect): Using awk to get the alert entry number 64
```
awk -v RS="" 'NR==63' alert
```
Note: Later I discovered that I should have used the log file and not the alert one.

Approach: Using snort for the package 63
```
sudo snort -r snort.log.1733753571 -n 63
```
Note: It reads 63 packages, go to the last one and get the answer.

##### What is the ACK number of packet 64?

Same approach as above, using number 64 this time
```
sudo snort -r snort.log.1733753571 -n 64
```

##### What is the SEQ number of packet 62?

Same technique as above.

##### What is the TTL of packet 65?

Same technique as above.

##### What is the source IP of packet 65?

Same technique as above.

##### What is the source port of packet 65?

Same technique as above.

## Task 3

Let's create IDS Rules for FTP traffic!

#### Write a single rule to detect "all TCP port 21"  traffic in the given pcap.

```
alert tcp any any <> any 21 (msg:"Incoming TCP traffict at port 21";sid:100001;rev:1;)
```

Run snort
```
sudo snort -c local.rules -A full -d -v -l . -r ftp-png-gif.pcap
```

Random note: -d flag outputs the application-layer data (payload)

##### What is the FTP service name?

```
sudo strings snort.log.1733757097 | grep -i service
```

```
sudo cat snort.log.1733757097 | grep -ia service
```
Note: This command needs -a to skip the binary file error.

#### Write a rule to detect failed FTP login attempts in the given pcap.

```
alert tcp any any <> any 21 (msg:"Incoming TCP traffict at port 21";content:"530";sid:100001;rev:1;)
```

Note: The server responds with a 4xx or 5xx error code indicating the failure:
* 530: Authentication failed  (invalid username/password).

##### What is the number of detected packets?


#### Write a rule to detect successful FTP logins in the given pcap.

```
alert tcp any any <> any 21 (msg:"Incoming TCP traffict at port 21";content:"230";sid:100001;rev:1;)
```
Note: A successful FTP login is indicated by the 230 status code from the FTP server.

##### What is the number of detected packets?

```
sudo snort -c local.rules -A full -d -v -l . -r ftp-png-gif.pcap
```

#### Write a rule to detect FTP login attempts with a valid username but no password entered yet.

```
alert tcp any any <> any 21 (msg:"Incoming TCP traffict at port 21";content:"331";sid:100001;rev:1;)
```
Note: 331: User name OK, but a password is still required.

##### What is the number of detected packets?

```
sudo snort -c local.rules -A full -d -v -l . -r ftp-png-gif.pcap
```

#### Write a rule to detect FTP login attempts with a valid username but no password entered yet.

Using the same rule as above
```
alert tcp any any <> any 21 (msg:"Incoming TCP traffict at port 21";content:"331";sid:100001;rev:1;)
```


##### What is the number of detected packets?

Check the administrator attemps.
```
sudo strings snort.log.1733758277 | grep -i administrator
```

## TASK 4

Let's create IDS Rules for PNG files in the traffic!

#### Write a rule to detect the PNG file in the given pcap.

```
alert tcp any any <> any any (msg:"PNG  traffic";content:"PNG";sid:100001;rev:1;)
```

Investigate the logs and identify the software name embedded in the packet.

Command to run snort:
```
sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

Check the logs and look for the software:
```
sudo strings snort.log.1733758824
```

#### Write a rule to detect the GIF file in the given pcap.

```
alert tcp any any <> any any (msg:"GIF  traffic";content:"GIF";sid:100001;rev:1;)
```

Run snort:
```
sudo snort -r ftp-png-gif.pcap -c local.rules -l .
```

Read logs
```
sudo snort -r snort.log.1723778324 -X
```

## Task 5

#### Let's create IDS Rules for torrent metafiles in the traffic!

##### Write a rule to detect the torrent metafile in the given pcap.

```
alert tcp any any <> any any (msg:"Torrent  traffic";content:"torrent";sid:100001;rev:1;)
```
Note: The content is case sensitive.

Run snort
```
sudo snort -r torrent.pcap -c local.rules -l .
```

##### What is the name of the torrent application?

```
sudo strings snort.log.1733764452 | grep -i application
```

##### What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?

Note: MIME specifies the type of content being transmitted using headers like Accept for requests and Content-Type for responses.

```
sudo strings snort.log.1733764452 | grep -i accept
```

##### What is the hostname of the torrent metafile?

```
sudo strings snort.log.1733764452 | grep -i host
```

## Task 6

#### Let's troubleshoot rule syntax errors!

Run snort
```
sudo snort -c local-X.rules -r mx-1.pcap -A console
```

##### Fix the syntax error in local-1.rules file and make it work smoothly.

The error is a missing space between the rule header part and the rule options part.

##### local-2.rules

The SOURCE PORT part was missing.

##### local-3.rules

The issue was the use of the same sid:1000001.

##### local-4.rules

There was a typo (`:`) at the end of the second `msg`. There was also the use of the same sid. 

##### local-5 rule

Wrong use the direction of IPs (`<-` is not valid). Typo (`:`) after msg. Typo (`;`) for sid.

##### local-6 rule

The hex code in the rule correspond to "get" (lowercase), the fix is to have GET in uppercase.

It's missing the msg option, alerts without it don't make sense.

## TASK 7

Let's use external rules to fight against the latest threats!

##### Use the given rule file (local.rules) to investigate the ms1710 exploitation.

```
sudo snort -c local.rules -r ms-17-010.pcap -X
```

##### Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

```
alert tcp any any <> any any (msg: "\IPC$" Detected"; content:"|5C 49 50|C$";sid:100001;rev:1;)
```
Note: We can use hex (with or without combining ASCII)

##### What is the requested path?

Log and then check the content of the payload.

##### What is the CVSS v2 score of the MS17-010 vulnerability?

https://www.tenable.com/plugins/nessus/97737

## TASK 8

Let's use external rules to fight against the latest threats!

##### Use the given rule file (local.rules) to investigate the log4j exploitation.

```
sudo snort -c local.rules -r log4j.pcap -X
```

##### How many rules were triggered?.

Just use the console to get the unique sid ;)
```
sudo strings alert | grep "\[1:" | sort | uniq -c 
```

##### What are the first six digits of the triggered rule sids?

Read the sid and take the first 6 digits.

#### Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.

```
alert tcp any any <> any any (msg:"Size 770 and 855"; dsize:770<>855; sid:100001;rev:1;)
```

#### What is the name of the used encoding algorithm?

Scroll through the packets.

