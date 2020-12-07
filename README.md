YOU MUST HAVE PERMISSION BEFORE USING THIS TOOL - THIS IS DEVELOPED FOR CTF USE, FOR EXAMPLE ON TRYHACKME OR HACKTHEBOX!
# lfi-fuzz
A python script to enumerate and attempt to get code execution from LFI vulnerabilities

Usage: lfi-fuzz.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL, --url=URL     The URL you wish to test:
                        http://www.example.com/index.php?page=LFI
  --traversal-file=TRAVERSAL_FILE  (OPTIONAL)
                        Specify your own file to search for with LFI - by
                        default this is /etc/passwd, but some php filters will
                        add a file extension
  --filter=FILTER_STR (OPTIONAL)
                        An error string that appears commonly on the page when
                        you try to load in an invalid file: 'ERROR - cannot
                        find'. NOTE - this is case sensitive
  --custom-file-list=CUSTOM_LIST (OPTIONAL)
                        Specify your own list of files to attempt to find
                        through the LFI
  --read-file=FILE_TO_READ (OPTIONAL)
                        Specify your own file to attempt to read through the
                        LFI - must specify absolute path: passwd is not enough
                        to get the /etc/passwd


This script attempts to read the contents of the source code file for the page you are on (http://examplenet.com/index.php?param=test will attempt to extract the code behind the index.php page based on the base64 php filter read technique.

Then, the traversal path will be attempted to be found, followed by testing for code execution through PHP wrappers such as expect://.
Finally, the script will read a list of files from the wordlist (whether that is the default one supplied with the program, or the user defined one).

If the script finds any log files, it will attempt to check if log poisoning is possible, and automatically exploit this.


COMING SOON:
 - Fuzzing of various parameters to find one which may be able to be used for LFI
