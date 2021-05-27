# AndroCFG
Extract both control flow graphs and code parts from APK based on API calls. 

## Installation
```
pip install git+https://github.com/U039b/AndroCFG.git
```

## Usage
```
AndroCFG --help                                                                                           
usage: AndroCFG.py [-h] -a APK -o OUTPUT [-r RULES]

optional arguments:
  -h, --help            show this help message and exit
  -a APK, --apk APK     APK to be analyzed
  -o OUTPUT, --output OUTPUT
                        Output directory
  -r RULES, --rules RULES     (Optionnal)
                        JSON file containing rules
```
Example of usage:
``` 
AndroCFG -a my_apk.apk -o output
```