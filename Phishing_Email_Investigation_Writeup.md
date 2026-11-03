# The Greenholt Phish

### Analyzing a Malicious Email — Phishing Investigation

**Room:** [TryHackMe — The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)

## Scenario

A sales executive at Greenholt PLC reported a suspicious email received from a known customer. The message raised several red flags: a generic greeting, an unexpected request for a money transfer, and an unsolicited attachment. According to the employee, this behavior does not align with the customer's usual communication style. Concerned that the email may be malicious, the message was escalated to the SOC for investigation. The goal was to analyze the provided email sample and determine whether it was legitimate or part of a phishing attempt.

---

## Q1: What is the Transfer Reference Number listed in the email's Subject line?

I opened the email in Thunderbird by right-clicking → **Open With Thunderbird**, then checked the Subject line:

```
webmaster@redacted.org your: Transfer Reference Number:(09674321)
```

**Answer:** `09674321`

---

## Q2: What is the display name of the sender?

To view the display name, we just have to see the name that is displayed to us, not the real address — this is found in the **Reply-To** header:

```
Reply to Mr. James Jackson <info.mutawamarine@mail.com>
```

Here we can see the display name.

**Answer:** `Mr. James Jackson`

---

## Q3: What is the sender's email address?

*(Continuing to investigate the email headers.)*

The sender's email address can be seen in the mail, just below the name of the sender, Mr. James Jackson. The mail of the sender is:

**Answer:** `info@mutawamarine.com`

---

## Q4: What email address will receive a reply to this email?

Checking the Reply-To header again:

**Answer:** `info.mutawamarine@mail.com`

---

## Q5: What is the originating IP address of this email?

*(Beginning to analyze the message source.)*

For this, I clicked the **View** button in the top header of Thunderbird and then clicked **Message Source**. Then I used Ctrl+F to find the `Received:` header. In this, I got:

```
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810 helo=mutawamarine.com)
```

**Answer:** `192.119.71.157`

---

## Q6: Who is the owner of the originating IP?

*(Investigating the IP address from the previous question.)*

To investigate the IP I used **Cisco Talos**, and in the Owner Details section of the result I got the network owner:

| Network Owner | HostPapa |
|---|---|

**Answer:** `HostPapa`

---

## Q7: Run an SPF record check on the Return-Path domain. What is the full SPF record?

The Return-Path domain is `mutawamarine.com`, found from the `info@mutawamarine.com` address in the message source's **Return-Path** header.

To check the SPF record, I used this CLI command to check the TXT records for the domain `mutawamarine.com`:

```bash
dig +short TXT mutawamarine.com
```

Result:

```
"MS=842BCB91F2AB2807BE05D25DC690D1226B349676"
"v=spf1 include:spf.protection.outlook.com -all"
"MS=ms97822417"
```

The second string is the complete SPF record for this domain. (Tools like MXToolbox can also be used for this and the next question.)

**Answer:** `v=spf1 include:spf.protection.outlook.com -all`

---

## Q8: Perform a DMARC lookup for the Return-Path domain. What is the complete DMARC record?

I used this CLI command:

```bash
dig +short TXT _dmarc.mutawamarine.com
```

and got the final answer:

**Answer:** `v=DMARC1; p=quarantine; fo=1`

---

## Q9: What is the file name of the attachment found in the email?

At the bottom of the Thunderbird window, there's a file attachment with the name:

```
SWT_#09674321__PDF_.CAB
```

Make sure to add the underscores properly in the filename — it can also be confirmed in the message source under the `Content-Disposition` header.

**Answer:** `SWT_#09674321__PDF_.CAB`

---

## Q10: Download the attachment. What is its SHA256 hash?

Next to the file name there's a **Save** button on the right side — clicking it saves the file to the local machine. Then, from the command line:

```bash
sha256sum filename
```

to find the hash of the file:

**Answer:** `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

---

## Q11: Investigate the file hash using VirusTotal. What did you find?

In VirusTotal, this file was flagged as malicious by **49 out of 64** vendors, with the threat label: **Trojan / Ransomware**.

Other names the file has been seen under on VirusTotal include:

```
SWT_#09674321____PDF__.CAB
attachment.cab
a.CAB
application.rar
SWT__09674321____PDF__.CAB
test.CAB
download.rar
SWT_09674321____PDF__.CAB
attachment.CAB
2.rar
download.rar.txt
aaa
file.CAB
result
download.pdf
```

---

## Q12: What is the attachment's file size in KB?

In the email, the file size shown is 400 KB — but a more precise number was needed, which I got from the VirusTotal details result when I searched for the file hash in the previous question.

Basic properties from VirusTotal:

```
MD5          f4dd3456cdb1976a145c1179a4d461ec
SHA-1        5a2bb8188377c15c036843b4a6ab9b0c0f2c1607
SHA-256      2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
SSDEEP       12288:Mj6ygt8RoYqMAnuL8I0A81aBYoIm9+X3B4k56:EgqRJCuL87toIC+X3O
TLSH         T12C94238893562439A8F7385DAFD0CFB5EFE898E74E8F97709CFD609E5D140446205AC2
File type    RAR compressed
Magic        RAR archive data, v5
TrID         RAR compressed archive (v5.0) (61.5%) / RAR compressed archive (gen) (38.4%)
Magika       RAR
File size    400.26 KB (409,868 bytes)
```

**Answer:** `400.26 KB`

---

## Q13: Continuing the research — what is the actual file type of the attachment?

The actual file type is also mentioned in the same VirusTotal result above. Despite the `.CAB` extension used to disguise it, the file is actually a:

**Answer:** `RAR archive` (RAR compressed archive, v5)

---

## Summary

| # | Finding |
|---|---------|
| Transfer Reference Number | 09674321 |
| Display name used | Mr. James Jackson |
| Sender address | info@mutawamarine.com |
| Reply-To address | info.mutawamarine@mail.com |
| Originating IP | 192.119.71.157 |
| IP owner | HostPapa |
| SPF record | `v=spf1 include:spf.protection.outlook.com -all` |
| DMARC record | `v=DMARC1; p=quarantine; fo=1` |
| Attachment name | `SWT_#09674321__PDF_.CAB` |
| SHA256 hash | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| VirusTotal detections | 49/64 vendors — Trojan/Ransomware |
| Reported file size | 400.26 KB |
| Actual file type (disguised as .CAB) | RAR archive |

**Verdict:** Confirmed phishing/malware delivery attempt — a disguised malicious RAR archive masquerading as a `.CAB`/PDF transfer confirmation, sent from a spoofed/mismatched sender identity with a generic greeting and urgency-driven financial request, consistent with the employee's reported red flags.
