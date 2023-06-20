# iRedAdmin-Pro-SQL

### Free & open-source repository of iRedAdmin-Pro-SQL

This is a free upload of the latest "iRedAdmin-Pro-SQL" package (5.4). I hope some people will find this useful. I was looking for quite a while online but could not find a freely distributed copy, despite the license technically not stopping you from sharing it, as I mention below.

Since nobody else did it, I now will. The few modifications done to it are listed below. Thank me later! <br><br>

-----

### yoUrE brEAkInG tHE liCeNsE...

```console
The client is NOT allowed to redistribute or resell iRedAdmin-Pro (...) as your own product. 
```
aka. I AM allowed to redistribute iRedAdmin-Pro, acknowledging that it is their code, which I hereby do. I am not claiming this as my own product, this is their creation, not mine. I merely share it, as I disagree with having to pay for open-source code.

All copyright, and other -rights to iRedMail. <br><br>

### ... aND thE nEw EulA

Wrong again. In no way am I ever being told to agree to it. Furthermore, the EULA does not change the past. This is a modified, open-sourced copy of the product during a time where it was fine. Now, the new EULA would *in theory* break this for me. **HOWEVER**, I dont have to agree to it to download the update, I dont have to agree to it to install the update, and I am not asked to agree to it before usage. In fact, if git wouldnt have told me, I wouldnt even know. That being said, the EULA might as well not exist. At least thats its current legal status. This piss-poor "pweeease reawd" in the readme that nobody reads, doesnt help either. It asks you to read it, but never to accept or understand? Gosh, the legalese of some people is down atrociously bad<br><br>

-----

Only very few files were changed. Original check has been commented out so you can understand what it did before. 

```console
- libs/sysinfo.py
# This script did the actual check
  
- templates/default/panel/license.html
# Tiny change to remove the "Renew License" button
  
- static/default/css/screen.css
# ctrl+shift+I formatting & changed color from green to purple. 
# CSS file looks disgusting, refusing to clean that
```

Thats it <br><br>

-----

### Original Details

|Feature	                           | iRedAdmin (OSE) | iRedAdmin-Pro|
|------------------------------------|-----------------|--------------|
$\textcolor{orange}{\textsf{Localized Web Interface}}$<br>English, German, Spanish, French, Italian, Polish, Chinese, and more.	           |     X           |    X         |
$\textcolor{orange}{\textsf{RESTful API Interface}}$<br>Read our [API documentation](https://docs.iredmail.org/iredadmin-pro.restful.api.html) | | X |
$\textcolor{orange}{\textsf{Unlimited Mail Domains}}$<br>Host as many mail domains as you want | X | X |
$\textcolor{orange}{\textsf{Unlimited Mail Users}}$<br>With per-user mailbox quota control | X | X |
$\textcolor{orange}{\textsf{Unlimited Mailing List/Aliases}}$<br>Manage members, access policies | | X |
$\textcolor{orange}{\textsf{Unlimited Domain-Level Admins}}$<br>Either promote a mail user to domain admin role, or create a separated domain admin account		| | X |
$\textcolor{orange}{\textsf{Advanced Domain Management}}$<br>Domain-level mailbox quota, limit numbers of user/list/alias accounts, Relay, BCC, Alias, Domain, Catch-all, Backup MX, Throttling, Greylisting, Whitelists, Blacklists, Spam Policy, user password length and complexity control		| | X |
$\textcolor{orange}{\textsf{Advanced User Management}}$<br>Per-user BCC, Relay, Mail Forwarding, Alias Addresses, Throttling, Greylisting, Whitelists, Blacklists, Spam Policy, restrict login IP/network, Changing email address		| | X |
$\textcolor{orange}{\textsf{Self-Service}}$<br>Allow end user to manage their own preferences: Password, Mail Forwarding, Whitelists, Blacklists, Quarantined Mails, Spam Policy		| | X |
$\textcolor{orange}{\textsf{Service Control}}$<br>One click to enable/disable mail services for mail user: POP3, IMAP, SMTP, Sieve filter, Mail Forwarding, BCC, and more.		| | X |
$\textcolor{orange}{\textsf{Spam/Virus Quarantining}}$<br>Quarantine detected SPAM/Virus into SQL PostgreSQL database for later management (delete, release, whitelist, blacklist)		| | X |
$\textcolor{orange}{\textsf{View basic info of all sent and received emails}}$<br>Sender, Recipient, Subject, Spam Score, Size, Date | | X |
$\textcolor{orange}{\textsf{Throttling}}$<br>Based on: max size of single email, number of max inbound/outbound emails, cumulative size of all inbound/outbound emails		| | X |
$\textcolor{orange}{\textsf{Whitelisting, Blacklisting}}$<br>Based on: IP addresses/networks, Sender address, Sender domain name | | X |
$\textcolor{orange}{\textsf{Searching Account}}$<br>Searching with display name or email address, domain name | | X |
$\textcolor{orange}{\textsf{Log Maildir Path of Deleted Dail User}}$<br>You can delete the mailbox on file system later, either manually or with a cron job		| | X |
$\textcolor{orange}{\textsf{Log Admin Activities}}$<br>Account creation, activation, removal, password change, and more. | | X |
$\textcolor{orange}{\textsf{Fail2ban Integration}}$<br>View info of banned IP address (Country/City, reverse DNS name), log lines which triggerred the ban (easy to troubleshoot why the ban happened), and unban it with one click		| | X |
$\textcolor{orange}{\textsf{Last login track}}$<br>View the time of user last login via IMAP and POP3 services, also the time of last (locally) delivered email		| | X |
$\textcolor{orange}{\textsf{Export all managed mail accounts}}$| | X |
$\textcolor{orange}{\textsf{Export statistics of admins}}$| | X |

<br><br>

-----

### My wallet is crying now. Please give this repo a star to cheer me up

![2023-04-10-064957](https://user-images.githubusercontent.com/104512346/230828290-cf3aec7c-a850-494a-94f9-0f739ffc6b48.png)
