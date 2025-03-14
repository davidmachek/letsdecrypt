from colorama import *
import time
def create_space_info(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}] [{Fore.LIGHTGREEN_EX}inf{Fore.RESET}] {Fore.LIGHTBLACK_EX}┌─{Fore.RESET} {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] [inf] {Fore.LIGHTBLACK_EX}┌─{Fore.RESET} {msg}")
def space(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}]       {Fore.LIGHTBLACK_EX}├─{Fore.RESET} {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}]       {Fore.LIGHTBLACK_EX}├─{Fore.RESET} {msg}")
def end_space(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}]       {Fore.LIGHTBLACK_EX}└─{Fore.RESET} {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}]       {Fore.LIGHTBLACK_EX}└─{Fore.RESET} {msg}")
def info(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}] [{Fore.LIGHTGREEN_EX}inf{Fore.RESET}] {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] [inf] {msg}")
def error(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}] [{Back.RED}err{Back.RESET}] {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] [err] {msg}")
def warning(msg,write=False,print2=True):
        if print2:
            print(f"[{time.strftime('%H:%M:%S')}] [{Fore.YELLOW}war{Fore.RESET}] {msg}")
            if write != False:
                with open(write,"a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] [war] {msg}")