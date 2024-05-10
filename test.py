import re

# The string to extract the hostname from
input_string = "location: https://test.com?something=something"

# Regular expression pattern to match the hostname
pattern = r"(?<=https:\/\/)[^\/\?]+"

# Using re.search() to find the first match of the pattern
match = re.search(pattern, input_string)

# Extracting and printing the hostname if a match is found
if match:
    hostname = match.group()
    print(hostname)
else:
    print("Hostname not found")