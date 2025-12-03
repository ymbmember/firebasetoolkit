## **SCRIPTS WERE MADE FOR https://forum.duty-free.cc COMPETITION**

## **Scripts list:**
 - extractor.py
 - realtimechecker.py
 
**extractor.py**
Allows you to extract firebase configs from web pages
![](https://raw.githubusercontent.com/ymbmember/firebasetoolkit/refs/heads/main/extractor.jpg)

Options:
```
  -v, --verbose
  -o OUTPUT, --output OUTPUT
  --workers WORKERS
  --timeout TIMEOUT
 
You can also store the variables in a single file for future testing.
-odu <file> save databaseURL's (usefull for realtimechecker.py)
-osb <file> save storageBucket urls 
-oad <file> authDomain urls
```


**realtimechecker.py**
Checks for basic misconfigurations related to read and write access.
![](https://raw.githubusercontent.com/ymbmember/firebasetoolkit/refs/heads/main/checker.jpg)


Options:
```
  -u URL, --url URL (single url to test)
  -l LIST, --list <file> (list of urls to test)
  --write (without this flag, the script will only check for read permission)
  -v, --verbose
  -w WORKERS, --workers WORKERS
  --timeout TIMEOUT
  -or OUT_READ, --out-read <file> (save the URLs that have read permissions.)
  -ow OUT_WRITE, --out-write <file> (save the URLs that have write permissions.)
```

## **https://forum.duty-free.cc - best underground hacking forum**
