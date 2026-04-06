# Wireshark HTTP Export Writeup

## Challenge: Extract Flag from PCAPNG using Wireshark

---

## Method: Export HTTP Objects

### Step 1: Open PCAPNG File in Wireshark
```bash
wireshark 1.pcapng
```

Or use GUI:
- File → Open
- Select `1.pcapng`

---

### Step 2: Export All HTTP Objects
**Menu Path:**
```
File → Export Objects → HTTP...
```

<img width="637" height="674" alt="image" src="https://github.com/user-attachments/assets/ded09b8f-9064-43b1-9095-9954bbaf9b3e" />


This opens the "Export Objects" dialog showing all HTTP files/responses captured.

---

### Step 3: List of Exported Objects

The export shows these files:

| Filename | Size | Type | Notes |
|----------|------|------|-------|
| %2f | 4.9K | HTML | Root page (/) |
| index.php | 4.9K | HTML | Index page |
| login.php | 5.4K | HTML | Login form |
| signup.php | 5.9K | HTML | Signup form |
| **newuser.php** | 144 bytes | Form Data | **POST request body** |
| **newuser(1).php** | 747 bytes | HTML | **SERVER RESPONSE - FLAG HERE!** |

---

### Step 4: Open newuser(1).php Response

This is the **HTTP response** from the server after form submission.

**Content:**
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" 
  "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>add new user</title>
</head>
<body>
<div id="masthead"> 
  <h1 id="siteName">ACUNETIX ART</h1> 
</div>
<div id="content">
  <p>You have been introduced to our database with the above informations:</p>
  <ul>
    <li>Username: flag{}</li>
    <li>Password: $JG1{p4cket_c4ptured}</li>
    <li>Name: cyber</li>
    <li>Address: </li>
    <li>E-Mail: </li>
    <li>Phone number: </li>
    <li>Credit card: </li>
  </ul>
  <p>Now you can login from <a href='http://testphp.vulnweb.com/login.php'>here.</p>
</div>
</body>
</html>
```

---

## The Flag

Right there in the HTML response:
```html
<li>Password: $JG1{p4cket_c4ptured}</li>
```

**Flag:** `$JG1{p4cket_c4ptured}`

---

## Key Findings

### Two newuser.php Files
1. **newuser.php** (144 bytes) - The POST request body (form submission)
   ```
   uuname=flag%7B%7D&upass=%24JG1%7Bp4cket_c4ptured%7D&...
   ```

2. **newuser(1).php** (747 bytes) - The HTTP response from server
   ```html
   <li>Password: $JG1{p4cket_c4ptured}</li>
   ```

Wireshark automatically numbers duplicate filenames with `(1)`, `(2)`, etc.

---

## Why This Method Works

✅ **Complete Visibility** - Shows request AND response  
✅ **Automatic Parsing** - HTTP objects extracted automatically  
✅ **Easy Navigation** - GUI makes it simple to browse files  
✅ **Response Body** - Server's response clearly shows flag in HTML  
✅ **No Decoding Needed** - Response is plaintext HTML  

---

## Wireshark GUI Steps Summary

1. Open `1.pcapng` in Wireshark
2. Menu: **File → Export Objects → HTTP**
3. Dialog shows all exported objects
4. Click on **newuser(1).php** 
5. Click **Save** or **Save All**
6. Open saved file with text editor
7. Find line: `<li>Password: $JG1{p4cket_c4ptured}</li>`
8. **Flag extracted!** ✓

---

## Comparison: Request vs Response

| File | Type | Content |
|------|------|---------|
| newuser.php | POST Body | `upass=%24JG1%7Bp4cket_c4ptured%7D` (URL-encoded) |
| newuser(1).php | Response | `Password: $JG1{p4cket_c4ptured}` (plaintext HTML) |

The response file is much easier to read - the flag is in plaintext without URL encoding!

---

## Final Flag

```
$JG1{p4cket_c4ptured}
```

---

## Security Insights

🔴 **Vulnerabilities Found:**
- HTTP instead of HTTPS (plaintext transmission)
- Form data visible in network traffic
- Server response echoes back user input in HTML
- No input validation/sanitization
- Credentials sent unencrypted

---

## Difficulty: Very Easy
**Category:** Network Forensics  
**Tool:** Wireshark GUI  
**Technique:** HTTP Object Export  
**Time:** < 1 minute
