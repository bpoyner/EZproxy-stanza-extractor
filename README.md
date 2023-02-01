# stanza.py

stanza.py is a Python script for extracting stanzas from the OCLC EZproxy website.  Extracted stanzas can be sent to files or stdout.

## Installation

Requires Python3 and the packages BeautifulSoup4, requests, and html5lib

$ sudo pip3 install bs4 requests html5lib

## Usage

```
./stanza.py --outdir=/usr/local/ezproxy/databases https://help.oclc.org/Library_Management/EZproxy/Database_stanzas/EBSCO_Information_Services
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
