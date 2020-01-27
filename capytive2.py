#!/usr/bin/env python3
"""
 Copyright (c) 2019 anicca048
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
"""
"""
 Warning:  A large amount of data is generated in a way that an identity change
           of the captive portal will not brake anything, but any major change
           to the portal itself will probably brake everything.
"""

import argparse
import requests
import random
import time
import sys
import re

# Make sure the right version of python is being used.
try:
    assert sys.version_info >= (3, 0, 0), "python version error"
except AssertionError:
    print("error: python3 is required to run this program!")
    exit(1)

# Entry function.
def main(user_email, user_agent, user_wait):
    # Generate random email if one was not provided.
    if not user_email:
        user_email = gen_email()

        if not verify_email(user_email):
            print("error: invalid random email!")
            print("email:", user_email)
            print("rand_src file may have been corrupted or tampered with!")
            exit(1)

    # Generate random useragent if one was not provided.
    if not user_agent:
        user_agent_name, user_agent = gen_agent()
    else:
        user_agent_name = "Custom"

    # Set random wait time between 5 - 10 seconds upon user request.
    if user_wait:
        wait_time = ((random.randint(0, 5) % 5) + 5)

    # Original http request url (gets hijacked by captive portal).
    original_url = "http://www.google.com/"

    # Strip protocol from URL for HTTP header use.
    original_url_short = original_url.split("://")[1]

    # TLS website used for post portal login network test.
    network_test_url = "https://www.google.com/"

    #Simple header for the GET requests
    get_request_header = { 'User-Agent' : user_agent}

    #Correct form options for the POST request (not exactly secure auth huh?)
    post_request_form = {
                         'buttonClicked' : "4",
                         'redirect_url' : original_url_short,
                         'err_flag' : "0",
                         'agree' : "on",
                         'email' : user_email,
                         'Submit' : "Accept"
                        }

    print("\ncapytive2")

    print("[+] sending initial request...")

    # Send http request to non-TLS site (this will be hijacked by portal)
    get_request = send_get_request(request_header = get_request_header,
                                   request_url = original_url)

    # Parse content refresh redirect URL.
    try:
        # Pull the redirect URL from response.
        redirect_url = (((get_request.text).split("URL="))[1]).split("\"")[0]

        # Pull the post URL from redirect URL.
        login_url = (((redirect_url).split("url="))[1]).split("&")[0]

        # Pull origin header value from login URL.
        post_request_header_origin = login_url.split("/login.html")[0]
    except ValueError:
        print("[!] error: invalid redirect!")
        print("[!] either there is no portal or portal core has changed!")
        exit(1)
    except IndexError:
        print("[!] error: invalid redirect!")
        print("[!] either there is no portal or portal core has changed!")
        print("[!] find a dev and yell at 'em 'bout it!")
        exit(1)

    print("[+] sending login page request...")

    # Send request for redirect url (for sake of appearance not for real use).
    get_request = send_get_request(request_header = get_request_header,
                                   request_url = redirect_url)

    # Build post header from data recieved when original request was redirected.
    post_request_header = {
                           'User-Agent' : user_agent,
                           'Origin' : post_request_header_origin,
                           'Referer' : redirect_url,
                          }

    if user_wait:
        print("[+] waiting for", wait_time, "seconds...")
        time.sleep(wait_time)

    print("[+] sending login authentication data...")

    # Post portal authentication data.
    post_request = send_post_request(request_header = post_request_header,
                                     request_url = login_url,
                                     request_form = post_request_form)

    # Portal expects a retrieval of the pre-highjacked url.
    print("[+] resending initial request...")

    send_get_request(request_header = get_request_header,
                      request_url = original_url)

    # Double check if network access is working (by retrieving TLS site).
    print("[+] sending network test request...")

    send_get_request(request_header = get_request_header,
                      request_url = network_test_url)

    # Login process complete (all Ur Portalz R Belong to Me!).
    print("[+] captive portal login complete.")
    print()
    print("[#] email:     ", user_email)
    print("[#] useragent: ", user_agent_name)
    print("[#] portal URL:", login_url)

# Make sure we have a valid email address as defined by the portal.
def verify_email(user_email):
    # Non RFC format (based on the server's js regex).
    user_email_format = "[a-zA-Z0-9\.]+@[a-zA-Z0-9\.]+\.[a-zA-Z]{2,4}$"

    # Check email format adhearence.
    if not re.match(user_email_format, user_email):
        return False

    return True

# Get file size for randomness limits.
def get_file_size(file_path):
    # Find out how many lines in textfile.
    file_size = 0

    try:
        with open(file_path, "r") as file:
            for i, line in enumerate(file):
                pass

            file_size = (i + 1)
    except FileNotFoundError:
        print("[!] error:", file_path, "is missing!")
        exit(1)
    except NameError:
        print("[!] error:", file_path, "has no lines!")
        exit(1)

    return file_size

# Pull one line at random from text file.
def get_file_line(file_path, file_size):
    # Generate random line number using line count of file as limit.
    random_line = None

    try:
        with open(file_path, "r") as file:
            line_num = (random.randint(1, file_size) % file_size)

            for i, line in enumerate(file):
                if i == line_num:
                    random_line = line.split('\n')[0]
                    break
    except FileNotFoundError:
        print("[!] error:", file_path, "is missing!")
        exit(1)
    except NameError:
        print("[!] error:", file_path, "has no lines!")
        exit(1)

    return random_line

# Generate random email address from lists of names and domains.
def gen_email():
    # Files with names and domains (randomly sorted).
    first_names = "rand_src/firstname.txt"
    last_names = "rand_src/lastname.txt"
    domains = "rand_src/domains.txt"

    # Generate random first name.
    user_email = get_file_line(first_names, get_file_size(first_names))
    
    # Possibly generate period between first and last name.
    if random.randint(1,2) == 2:
        user_email += "."
    
    # Generate random lastname.
    user_email += get_file_line(last_names, get_file_size(last_names))

    # Possibly generate trailing numbers after last name.
    if random.randint(1,2) == 2:
        user_email += str(random.randint(1,999) % 999)

    # Generate random email domain after username.
    user_email += "@"
    user_email += get_file_line(domains, get_file_size(domains))

    return user_email

# Generate random useragent from list.
def gen_agent():
    # File with useragent strings and common names for them (randomly sorted).
    user_agents = "rand_src/useragent.txt"

    # Generate random useragent.
    user_agent_full = get_file_line(user_agents, get_file_size(user_agents))
    user_agent_name = user_agent_full.split('[|]')[0]
    user_agent = user_agent_full.split('[|]')[1]

    return user_agent_name, user_agent

# Send a http GET request.
def send_get_request(request_header, request_url):
    try:
        get_request = requests.get(headers = request_header, url = request_url)
    except requests.exceptions.ConnectionError:
        print("[!] error: failed to connect!")
        exit(1)
    except requests.exceptions.RequestException as exc:
        print("[!] error: GET request failed:", exc)
        exit(1)

    # Check for failure status code.
    if get_request.status_code != 200:
        print("[!] Error: GET request rejected!")
        exit(1)

    return get_request

# Send a http POST request.
def send_post_request(request_header, request_url, request_form):
    try:
        post_request = requests.post(headers = request_header,
                                     url = request_url,
                                     data = request_form)
    except requests.exceptions.ConnectionError:
        print("[!] error: failed to connect!")
        exit(1)
    except requests.exceptions.RequestException as exc:
        print("[!] error: POST request failed:", exc)
        exit(1)

    # Check for failure status code.
    if post_request.status_code != 200:
        print("[!] error: POST request rejected!")
        exit(1)

    return post_request

# External use gaurd.
if __name__ == "__main__":
    # Setup cmdline argument parser.
    parser = argparse.ArgumentParser(
        prog="capytive2.py",
        description="Captive portal autologin bot script.")
    
    # Add arguments to parser.
    parser.add_argument("-w", "--wait", action="store_true", 
                        help="wait for a random ammount of time before login")
    parser.add_argument("-e", "--email",
                        help="provide custom email address for authentication")
    parser.add_argument("-u", "--useragent",
                        help="provide custom useragent for web requests")
    
    # Fetch arguments from sys.argv[].
    args = parser.parse_args()

    # Make sure email is formatted properly.
    if args.email:
        if not verify_email(args.email):
            print("error: invalid email address!")
            print("ex: username@domain.sfx\n")
            print("username / domain, alphanumeric chars and periods only.")
            print("suffix, alphabetic chars only and must be 2-4 chars long.")
            exit(1)

    # Start entry point function.
    main(user_email = (None if not args.email else args.email),
         user_agent = (None if not args.useragent else args.useragent),
         user_wait = (False if not args.wait else True))
