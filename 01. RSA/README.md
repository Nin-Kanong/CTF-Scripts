<h1 align="center"> Guide </h1>




### Identify

<img width="1711" height="115" alt="image" src="https://github.com/user-attachments/assets/6a20c7cb-e37b-4650-be5e-15b19457d7c8" />


Execute:
````py
python3 rsa_ctf_solver.py --host chatelaine.cylabacademy.net --port 41131 --samples 3
````



---


### Download:

On terminaL:
````shell
wget -O weak_rsa_solver.py "https://raw.githubusercontent.com/Nin-Kanong/CTF-Scripts/main/01.%20RSA/weak_rsa_solver.py"
````

````shell
chmod +x weak_rsa_solver.py
````

---


## Execute

````shell
python3 weak_rsa_solver.py --host <domain> --port <port>
````

### Read from a Text File
````shell
python3 weak_rsa_solver.py --file banner.txt
````


### Manual Input
````
python3 weak_rsa_solver.py --n 19908582... --e 65537 --c 77381944...
````


----
