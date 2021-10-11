# AndroCFG
Extract both control flow graphs and code parts from APK based on API calls.

## Installation
```
pip install git+https://github.com/U039b/AndroCFG.git
```

## Usage
```
usage: AndroCFG.py [-h] -a APK -o OUTPUT [-r RULES] [-f {bmp,html,raw}]

optional arguments:
  -h, --help            show this help message and exit
  -a APK, --apk APK     APK to be analyzed
  -o OUTPUT, --output OUTPUT
                        Output directory
  -r RULES, --rules RULES
                        JSON file containing rules
  -f {bmp,html,raw}, --file {bmp,html,raw}
                        Sets the output file type for the code extraction (bmp,
                        html or raw). Default is bmp
```
Example of usage:
```
AndroCFG -a my_apk.apk -o output
```
