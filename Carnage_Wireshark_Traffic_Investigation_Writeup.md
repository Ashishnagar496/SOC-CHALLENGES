# Carnage

### Analyzing Malicious Network Traffic with Wireshark

**Credit:** Brad Duncan, for capturing and sharing this traffic with the InfoSec community.

## Scenario

Eric Fischer from the Purchasing Department at Bartell Ltd received an email from a known contact with a Word document attachment. Upon opening the document, he accidentally clicked "Enable Content." The SOC Department immediately received an alert from the endpoint agent that Eric's workstation was making suspicious outbound connections. The pcap was retrieved from the network sensor and handed over for analysis.

**Task:** Investigate the packet capture and uncover the malicious activities.

 **Note:** No direct interaction is required with any domains or IP addresses in this challenge.

---

## Q1: What was the date and time for the first HTTP connection to the malicious IP? (yyyy-mm-dd hh:mm:ss)

First of all, I used the display filter `http`. In the very first HTTP packet, I got a GET request with an endpoint like `/incid%20-conci%25/documents.zip`.

The downloaded file here is `documents.zip`, which is also the answer for the next question.

In the protocol details pane, under the Frame section, I got the field **Arrival Time**, which was:

**Answer:** `2021-09-24 16:44:38` (Sep 24, 2021 16:44:38.990412000 UTC)

---

## Q2: What is the name of the zip file that was downloaded?

**Answer:** `documents.zip`

---

## Q3: What was the domain hosting the malicious zip file?

For this, in the same packet details, under the Hypertext Transfer Protocol section, I got the Host field:

**Answer:** `attirenepal.com`

---

## Q4: Without downloading the file, what is the name of the file inside the zip?

For this, we have to get the hash of the file so we can analyze it in VirusTotal to get the name of the files inside the zip.

I clicked on **File → Export Objects → HTTP** in the toolbar, got the `documents.zip` object, saved it to my device, and used `sha256sum` to get the file hash. I then used that hash in VirusTotal to analyze the file.

From VirusTotal, out of 65 vendors, **42** flagged this file as malicious, with the threat category **Trojan Downloader**.

In the file details, the file size was **193.48 KB**, and other names for the file included: `documents.zip`, `malware documents.zip`, `DANGEROUS`.

In the contained files section, I didn't get the actual filename, but I did get the extension type: `.xls`.

So I went back to the HTTP GET request containing `documents.zip` in its endpoint, right-clicked it, and selected **Follow → TCP Stream**. In the new window, I used the search option and searched for the `.xlsx` keyword. I got only one match:

**Answer:** `chart-1530076591.xls`

---

## Q5: What is the name of the web server of the malicious IP from which the zip file was downloaded?

To find the web server name, I checked the HTTP responses using the display filter `http.response`.

In the first packet returned, packet number **2173**, I got the server name — this was the response to the GET request from Q1.

**Answer:** `LiteSpeed`

---

## Q6: What is the version of the web server from the previous question?

For the version, I looked at the `X-Powered-By` header in the response, which showed:

**Answer:** `PHP/7.2.34`

---

## Q7: Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved?

The hint gave a time frame to inspect, so I filtered to that window and used TLS handshake type 1 to find the relevant traffic:

```
tls.handshake.type==1 and (frame.time >= "2021-09-24 16:45:11") && (frame.time <= "2021-09-24 16:45:30")
```

This returned 5 matching packets. I then used **Edit → Find Packet** in Wireshark to find any `.com` domains. On searching, I found three domains hidden in the hex value pane:

```
finejewels.com.au
self.events.data.microsoft.com  -> legit
client.wns.windows.com          -> legit
thietbiagt.com
new.americold.com
```

(Alternatively, the domain names can also be found in the **Server Name** field under TLS in the Protocol pane.)

**Answer:** `finejewels.com.au`, `thietbiagt.com`, `new.americold.com`

---

## Q8: Which certificate authority issued the SSL certificate to the first domain from the previous question?

The first domain from the previous question was found in packet number **2427**.

For this, I used VirusTotal and searched for the domain. In the details, I got the certificate authority — the one that issued the certificate was:

**Answer:** `GoDaddy`

---

## Q9: What are the two IP addresses of the Cobalt Strike servers? (sequential order)

There are some common ports typical C2 traffic uses, so I filtered according to that:

```
tcp.port == 80 || tcp.port == 443 || tcp.port == 8080 || tcp.port == 50050
```

Then, in **Statistics → Conversations**, I checked the "Limit to display filter" option. In the TCP section, I sorted the Bytes column in decreasing order, so the highest-transferred-byte conversations show up at the top.

On sorting, I got several IPs, but noticed 3–4 IPs sending noticeably more bytes compared to others:

```
104.83.84.137
185.125.204.174
185.106.96.158
136.232.34.70
```

On checking the first IP, I found it belongs to a CDN/cloud provider. The second and third IPs share the same first octet, `185`, and belong to an independent VPS provider — a classic C2 hosting pattern. They're also using ports 80 and 8080, a classic signature for C2 listeners.

Before confirming, I also performed some CTI (cyber threat intel) checks on VirusTotal for them. In the Community section, I found various comments identifying a Cobalt Strike server on two of these IPs.

**Answer:** `185.106.96.158`, `185.125.204.174`

---

## Q10: What is the Host header for the first Cobalt Strike IP address?

I used this filter:

```
ip.addr==185.106.96.158
```

Under the HTTP protocol section, I got the Host header as:

**Answer:** `ocsp.verisign.com`

---

## Q11: What is the domain name for the first IP address of the Cobalt Strike server?

Found in the Community section on VirusTotal:

```
survmeter[.]live, /gscp[.]R/, 185[.]106[.]96[.]158, /gscp[.]R/
```

**Answer:** `survmeter.live`

---

## Q12: What is the domain name of the second Cobalt Strike server IP?

Similarly, for this one, found in the Community section:

```
securitybusinpuff[.]com, /jquery-3[.]3[.]1[.]min[.]js, 185[.]125[.]204[.]174, /jquery-3[.]3[.]1[.]min[.]js
```

**Answer:** `securitybusinpuff.com`

---

## Q13: What is the domain name of the post-infection traffic?

```
http.request.method == "POST"
```

**Answer:** `maldivehost.net`

---

## Q14: What are the first eleven characters the victim host sends out to the malicious domain in the post-infection traffic?

This was the full request URI:

```
http://maldivehost.net/zLIisQRWZI9/egl7fAgEMAQAAkJ7e2J2ZXh4Yn57eA==
```

**Answer:** `zLIisQRWZI9` (first eleven characters of the URI path)

---

## Q15: What was the length of the first packet sent out to the C2 server?

This was the first POST request.

**Answer:** `281`

---

## Q16: What was the Server header for the malicious domain from the previous question?

I clicked on the first POST request and followed the TCP stream to find the server string (visible in the first response headers from the server in the TCP stream), and got this:

**Answer:** `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4`

---

## Q17: The malware used an API to check the victim's IP address. What was the date and time of the DNS query for this IP-check domain? (yyyy-mm-dd hh:mm:ss UTC)

I used a simple filter:

```
dns contains "api"
```

In packet number **24149**, I got an API domain — `api.ipify.org`, which is a popular, free web service used by programs to discover their own public IP address.

Arrival time was:

**Answer:** `2021-09-24 17:00:04` (Sep 24, 2021 17:00:04.233864000 UTC)

---

## Q18: What was the domain in the DNS query from the previous question?

**Answer:** `api.ipify.org`

---

## Q19: There was some malicious spam (malspam) activity. What was the first MAIL FROM address observed in the traffic?

For this, I used this filter, covering the common SMTP ports:

```
smtp and tcp.port == 25 or tcp.port == 587 or tcp.port == 465
```

I got one SMTP packet with the MAIL FROM address:

**Answer:** `farshin@mailfa.com`

---

## Q20: How many packets were observed for the SMTP traffic?

Just use the filter `smtp` and check the packet count shown at the bottom of the Wireshark window (status bar "Displayed" count) to get the total number of SMTP packets.

*(Count to be confirmed directly from the capture — apply the `smtp` filter and read the displayed packet total.)*

---

## Summary

| Stage | Finding |
|---|---|
| Initial delivery | Malicious `documents.zip` downloaded from `attirenepal.com` at 2021-09-24 16:44:38 UTC |
| Payload inside zip | `chart-1530076591.xls` (macro-enabled Excel downloader, 42/65 VT detections) |
| Delivery web server | LiteSpeed, PHP/7.2.34 |
| Secondary payload domains | finejewels.com.au, thietbiagt.com, new.americold.com |
| SSL cert authority (1st domain) | GoDaddy |
| Cobalt Strike C2 servers | `185.106.96.158` (survmeter.live) and `185.125.204.174` (securitybusinpuff.com) |
| Post-infection C2 domain | maldivehost.net |
| First C2 POST request | `zLIisQRWZI9...` (281 bytes), server: Apache/2.4.49 (cPanel) |
| IP-check (API) activity | DNS query to `api.ipify.org` at 2021-09-24 17:00:04 UTC |
| Malspam activity | MAIL FROM `farshin@mailfa.com` |

**Verdict:** Confirmed multi-stage infection chain — malicious document delivery → Excel-based downloader → Cobalt Strike C2 beaconing over two independently-hosted VPS IPs → victim IP enumeration via a public API → associated malspam activity, consistent with a known Cobalt Strike-based commodity malware campaign.
