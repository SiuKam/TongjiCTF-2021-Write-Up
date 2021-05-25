# TongjiCTF 2021 Write Up
## 1. Misc
### 1.1. Sanity Check
使用HexChat登入提供的IRC服务器`irc.ctf.huangduligong.com/6667`，得到messa of the day:
```
* irc.ctf.huangduligong.com message of the day
*   _____                         _  _  _____  _____ ______   _____  _____  _____  __  
*  |_   _|                       (_)(_)/  __ \|_   _||  ___| / __  \|  _  |/ __  \/  | 
*    | |    ___   _ __    __ _    _  _ | /  \/  | |  | |_    `' / /'| |/' |`' / /'`| | 
*    | |   / _ \ | '_ \  / _` |  | || || |      | |  |  _|     / /  |  /| |  / /   | | 
*    | |  | (_) || | | || (_| |  | || || \__/\  | |  | |     ./ /___\ |_/ /./ /____| |_
*    \_/   \___/ |_| |_| \__, |  | ||_| \____/  \_/  \_|     \_____/ \___/ \_____/\___/
*                         __/ | _/ |                                                   
*                        |___/ |__/                                                    
*  
*  欢迎参加 TongjiCTF 2021!
*  
*  ------------------------------------------------------------
*  Flag 在频道 #CTF 中。比赛愉快！
*  
*  Find flag in channel #CTF.
*  ------------------------------------------------------------
*  
*  本 IRC 服务器仅为比赛临时搭建。官方通知&交流群：QQ 203799138。
*  
*  有意加入同济 CTF 战队或交流各种信息安全资讯者可解下题：
*  dWdnY2Y6Ly9xdmZwYmVxLnR0L1I5THI1UVJGaWo= （注：非 TongjiCTF 2021 赛题）。
```
根据提示进入`#CTF`，可见flag：`tjctf{w31comE_tO_70n6jICtf2021}`
### 1.2. NowYouSeeMe
得到文件`flag.txt`，打开为空。使用010 Editor打开，发现大量重复数据`E2 80 8B`与`E2 80 8D`，推测使用二进制编码，将`E2 80 8B`替换为0、`E2 80 8D`替换为1可得：
```
0111010001101010011000110111010001100110011110110100001001101100010001010110110100110001011100110100100000110001011011100110010101111101
```
借助二进制转ASCII工具，得到flag：`tjctf{BlEm1sH1ne}`
### 1.3. 迟到的签到
赛题提示为第一届TongjiCTF的签到题，Google到[TongjiCTF 2016](https://github.com/brant-ruan/TongjiCTF-2016)的存档，找到签到题，得到flag：`CTF{Hack_For_Fun}`
### 1.4. Ping
仅给出一个域名`ping.ctf.tongji.edu.cn`
根据第一条提示：
>The Domain Name System database does not only store ip records.   

尝试借助dig工具查看其解析记录：`dig ping.ctf.tongji.edu.cn`，得到响应：
```
;; ANSWER SECTION:
ping.ctf.tongji.edu.cn. 150     IN      A       10.10.175.204
```
未见异常，尝试获取TXT解析记录：`dig ping.ctf.tongji.edu.cn txt`，得到响应：
```
;; ANSWER SECTION:
ping.ctf.tongji.edu.cn. 300     IN      TXT     "TUQ1.R2V0TXlGbGFn"
```
发现信息`TUQ1.R2V0TXlGbGFn`，对其进行BASE64解码，并保留句点，得到关键信息`MD5.GetMyFlag`，对`GetMyFlag`进行MD5加密，得到`ffd8d776995c2f7e5fa83f581118af59`。  
根据第二条提示：
>RFC792 => nping  

查阅资料，得知[ICMP协议可以传输数据](https://www.anquanke.com/post/id/152046)，使用提示中的nping工具，将MD5加密后的数据传输过去：  
`sudo nping --icmp -c 1 --data-string 'ffd8d776995c2f7e5fa83f581118af59' ping.ctf.tongji.edu.cn`  
并用Wireshark抓包，在响应中找到flag：`tjctf{90_CH@7_w17h_iCMp}`   

![flag of ping](https://github.com/SiuKam/TongjiCTF-2021-Write-Up/blob/main/ping.png)
### 1.5. Can you hear me
题目提供一个exe文件，但Windows下无法执行，使用binwalk分析  
`binwalk can_you_hear_me.exe`  
发现文件中包含一个linux程序与一个加盐的加密文件：
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
14501         0x38A5          OpenSSL encryption, salted, salt: 0xBBF56A16C28519AA
```
linux下尝试运行，仅有一句输出命令。使用010 Editor打开，在14501位置前发现关键信息：  
>Robot36, it's a little bit noisy here! Let's use AES-256-CBC.  

借助之前的无线电经验，猜测文件可能是Robot36编码的SSTV图像信息。  
首先用dd命令将加密文件分解出来  
`dd if=can_you_hear_me.exe of=encrypted skip=14501 bs=1`  
得到OpenSSL加密的文件encrypted，下一步尝试对文件进行解密。  
根据信息，其使用的加密方式为`AES-256-CBC`，用openssl将文件解密  
`openssl enc -aes-256-cbc -d -in encrypted -out result`  
对于密码，猜测了题目中的OoOoOOO、Can you hear me、can_you_hear_me、Robot36之后，发现密码是`Robot36`。得到解密后的文件result，拖进任意播放器，即可听到“熟悉”的SSTV编码信息了。随意找一个支持Robot36协议的SSTV软件进行解码，得到flag：`tjctf{wh1spErA1n}`  

![flag of sstv](https://github.com/SiuKam/TongjiCTF-2021-Write-Up/blob/main/sstv.png)

## 2. Crypto
### 2.1. QWZEFQ RZFHPB
得到flag的密文`tjctf{QWZRFQRZFHPBRZBPWFYPBZWWGMORZHP}`与一段密文：
>JWZRRFJZW JFVXPBR ZBP JUSSUOWG NMFYP PZRG YU DBPZQ. SZOG JZO DP DBUQPO PTPO FH YXP ZYYZJQPB UOWG QOUER RMHHFJFPOY JFVXPBYPLY ZOI XPOJP YXPG ZBP RMRJPVYFDWP YU Z JFVXPBYPLY-UOWG ZYYZJQ. RUSP JWZRRFJZW JFVXPBR XZTP Z RSZWW QPG RVZJP.  

直接丢入[quipquip](http://quipqiup.com/)进行解密，得到flag：`tjctf{KLASIKSAIFERSARELITERALLYUNSAFE}`
### 2.2. RSA
RSA算法题。  
在[factordb](http://factordb.com/index.php?query=84317643128708607432495077733134608588622348874489427870407251923929810609559)找到n的两个质因子p与q。
```
n = 84317643128708607432495077733134608588622348874489427870407251923929810609559
p = 321760841969931553949977153286481002041
q = 262050666614640645936555334884792107599
```
这里借助RSA Tool 2对密文c进行求解，得到  
`c = 69607053209523197398725623549991328996424141890955496991656354176005068195953`   
根据代码提示，`c = pow(m, e, N)`，则`m = pow(c, d, N)`，得到  
`m = 12259991521844680649011528228906052347476912746285817970476216308861`   
根据代码提示，`m = bytes_to_long(flag)`，则`flag = long_to_bytes(m)`，得到   
`flag = b'tjctf{faC70R1zATiON_i5_f@5T}'`    
### 2.3. Collision!
赛题给出php源码：
```php
<?php
  highlight_file(__FILE__);
  include('flag.php');
  if(isset($_GET['a']) && isset($_GET['b']))
  {
    $a = (string)$_GET['a'];
    $b = (string)$_GET['b'];
    if (strlen($a) > 500 || strlen($b) > 500) {
      die("Too long!");
    }
    if ($a === $b) {
      die("Don't play Tricks!");
    }
    if (!preg_match('/I believe/', $a) || !preg_match('/in SHA1!/', $b)) {
      die('Go away you unbeliever!');
    }
    if (sha1($a) !== sha1($b)) {
      die('You failed.');
    }
    echo $flag;
  }
?>
```
阅读可知，题目要求传入字符串a与字符串b，并满足一下四个条件
- 两个字符串的长度均小于500；
- 两个字符串不相等（===判断）；
- 字符串a包含字符串'I believe'，字符串b包含字符串'in SHA1!'；
- 两个字符串的sha1值相等。   

立即联想到[Google发出的两个SHA1值相同、内容不同的PDF](https://shattered.io/)，查阅[资料](https://ctf-wiki.org/crypto/hash/sha1/)可知：
>只要使用给定的前 320 字节，后面任意添加一样的字节获取的哈希仍然一样  

好办，利用两个urlencode之后给定的320字节，末尾均拼接上'I believe in SHA1!'即可：  
```
a=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01sF%DC%91f%B6%7E%11%8F%02%9A%B6%21%B2V%0F%F9%CAg%CC%A8%C7%F8%5B%A8Ly%03%0C%2B%3D%E2%18%F8m%B3%A9%09%01%D5%DFE%C1O%26%FE%DF%B3%DC8%E9j%C2/%E7%BDr%8F%0EE%BC%E0F%D2%3CW%0F%EB%14%13%98%BBU.%F5%A0%A8%2B%E31%FE%A4%807%B8%B5%D7%1F%0E3.%DF%93%AC5%00%EBM%DC%0D%EC%C1%A8dy%0Cx%2Cv%21V%60%DD0%97%91%D0k%D0%AF%3F%98%CD%A4%BCF%29%B1I believe in SHA1!
b=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01%7FF%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2V%0BE%CAg%D6%88%C7%F8K%8CLy%1F%E0%2B%3D%F6%14%F8m%B1i%09%01%C5kE%C1S%0A%FE%DF%B7%608%E9rr/%E7%ADr%8F%0EI%04%E0F%C20W%0F%E9%D4%13%98%AB%E1.%F5%BC%94%2B%E35B%A4%80-%98%B5%D7%0F%2A3.%C3%7F%AC5%14%E7M%DC%0F%2C%C1%A8t%CD%0Cx0Z%21Vda0%97%89%60k%D0%BF%3F%98%CD%A8%04F%29%A1I believe in SHA1!
```
传入，得到flag：`tjctf{sHA1_1$_pr@CT1c4Lly_BrOkeN}`  
## 3. Web
### 3.1 Collision?
类似上题，题目首先给出第一部分源码：
```php
$quests = [False, False];
if (isset($_GET['a']) and isset($_GET['b'])) {
  if ($_GET['a'] != $_GET['b']) {
    if (md5($_GET['a']) == md5($_GET['b'])) {
      $quests[0] = True;
    }
  }
}
//...
```
阅读可知，题目要求传入字符串a与字符串b，满足以下两个条件
- 两个字符串不相同
- 两个字符串的MD5值相同  

查阅得知，[PHP在处理哈希字符串时，会利用”!=”或”==”来对哈希值进行比较，它把每一个以”0E”开头的哈希值都解释为0，所以如果两个不同的密码经过哈希以后，其哈希值都是以”0E”开头的，那么PHP将会认为他们相同，都是0](https://muouim.github.io/2019/01/30/MD5%E7%A2%B0%E6%92%9E/)。任意选用一对值：
```
a=s878926199a
b=s155964671a
```
网页给出第二段代码：
```php
if (isset($_GET['c']) and isset($_GET['d'])) {
  if ($_GET['c'] != $_GET['d']) {
    if (sha1($_GET['c']) == sha1($_GET['d'])) {
      $quests[1] = True;
    }
  }
}
if ($quests[0] && $quests[1]) {
  echo $flag;
}
```
阅读可知，题目要求继续传入字符串c与字符串d，满足以下两个条件
- 两个字符串不相同
- 两个字符串的SHA1值相同  

不多说，再次利用上题，得到flag：`tjctf{pHp_i$_th3_8E5T_1@NgUAGe}`

### 3.2 TongjiAdmin
赛题为一登录页面，查看源码，发现注释
```html
<!-- 以防忘记： Admin:admin. -->
<!-- 我才不担心有人发现这个注释。让那些可恶的黑客们知道了登陆信息又怎样，反正只有通过同济的网站才能登陆。 -->
```
尝试使用Admin:admin登录，页面给出信息`Curse you, Hacker!`，考虑信息中的“通过同济的网站”。   
再次打开页面，进行登录，使用Burp进行Intercept，观察请求头：
```
POST /index.php HTTP/1.1
Host: 10.10.175.98:20080
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.175.98:20080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.175.98:20080/index.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

username=Admin&password=admin
```
结合注释给出的提示，联想到将Referer项的值改为`http://tongji.edu.cn`，发送至Repeater，Send请求，即可看到Response中包含的flag：`tjctf{F4nCY_W38$17E_P0Or_SecUr1TY}`

### 3.3. deleted
进入网站，仅有一行文字，观察源码、请求、响应等，均无异常。   
看到提示：
>I hate crawlers.  

联想到查看`robots.txt`，登入`http://10.10.175.98:20083/robots.txt`，得到信息：
```
Disallow: /source
```
不允许那更要看看了，进入`http://10.10.175.98:20083/source`，得到网站源码：
```python
from flask import Flask, request
from flask_cors import CORS
import html
import os


flag = open('flag', 'r')
os.remove('flag')

sourceFile = open('webApp.py', 'r')
sourceCode = html.escape(sourceFile.read())
sourceFile.close()

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route('/', methods=['GET'])
def index():
    return "Flag is deleted. You won't get it!"


@app.route('/source', methods=['GET'])
def getSource():
    return '<pre><code>' + sourceCode + '</code></pre>' 


@app.route('/getfile', methods=['GET'])
def getFile():
    fileName = request.args.get('file', '')
    try:
        with open(fileName, 'r') as file:
            return '<pre>' + html.escape(file.read()) + '</pre>'
    except:
        return "Error opening/reading file"


if __name__ == '__main__':
    app.run()
```
可见主程序使用`open`功能打开了flag，随后使用`os.remove`对flag进行了删除，但**未关闭句柄**。   
下文可见网站有3个分支，前两个分支已经出现，第三个分支用于读取文件，且对输入参数没有任何过滤与限制，可对系统下的任意目录进行读取。查阅[资料](https://www.cnblogs.com/youxin/p/4744652.html)可知，文件打开之后，会占用一个fd值，位置位于`/proc/pid/fd/`。这里pid直接用self代替，fd号未知，从0开始枚举，登入`http://10.10.175.98:20083/getfile?file=../../../../../proc/self/fd/0`进行尝试，当`fd = 3`时得到flag：`tjctf{dEl3tED_8u7_Not_S@FE}`

## 4. Reverse
### 4.1. baby_rev
题目提示为送分题，直接用010 Editor打开，发现flag：`tjctf{welCOME_To_rEvEr$3}`
### 4.2. PyMaster
题目给出pyc文件，使用uncompyle6进行反编译，得到源码：
```python
import base64, types

def encode(s):
    return types.FunctionType(compile(base64.b64decode(b'bGFtYmRhIHM6IGJhc2U2NC5hODVlbmNvZGUoYmFzZTY0LmI4NWVuY29kZShzLmVuY29kZSgidXRmLTgiKSkp'), '', 'eval'), globals())()(s)


s = input('Input the flag:')
ss = ''
bb = True
for i in s:
    if bb:
        ss += i
        bb = False
    else:
        ss = i + ss
        bb = True
else:
    print(['Error', 'Right!'][(encode(ss) == b'AP-T.:16.HD15K-/Uh;$CM"i$@Tl`;6WZK19ds(\\->>8;9kSQ0@sq0tGQ')])
```
阅读代码，可知最后一句的逻辑为判断`encode(ss)`与给定的byte值是否相等，阅读`encode`函数，发现其compile了一句base64编码的命令，将其解码以便于阅读，则encode函数的定义变为：
```python
def encode(s):
    return types.FunctionType(compile('lambda s: base64.a85encode(base64.b85encode(s.encode("utf-8")))', '', 'eval'), globals())()(s)
```
可知`encode(s)`执行以下操作：
1. 进行`utf-8`编码；
2. 进行BASE85编码（`b85encode`形式）；
3. 进行BASE85编码（`a85encode`形式）。

因此，对给定的byte值进行以下操作，即可得出ss的值：
1. 进行BASE85解码（`a85decode`形式）；
2. 进行BASE85解码（`b85decode`形式）；
3. 进行`utf-8`解码。

得到`ss = '}+oTp_T0_l@r0_o{tjtcfYud_3lYdcrcyHN+'`，再观察从s到ss的变换代码，瞎写一个从ss到s的变换代码：
```python
ss = '}+oTp_T0_l@r0_o{tjtcfYud_3lYdcrcyHN+'
k = 18
s = ss[k]
for i in range(k) :
    s += ss[k - (i + 1)]
    print(s)
    s += ss[k + (i + 1)]
    print(s)
```
得到flag：`tjctf{You_d0_r3@llY_d0cTr_cpyTHoN++}`
