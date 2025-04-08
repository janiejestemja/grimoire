# Prefix
---

*Fragments of knowledge*.

Grimoire is a metaphorical and esoteric structure used to organize knowledge about programming and computing concepts. It includes chapters on Shapeshifting (environment), Astral Charts (networking), Dark Arts (memory handling), Divinations (data science) and Oracles (artificial intelligence).

Table of Contents
- [Shapeshifting](#i-shapeshifting-environment)
- [Astral Charts](#ii-astral-charts-networking)
- [Dark Arts](#iii-dark-arts-low-level)
- [Divinations](#iv-divinations-data-science)
- [Oracles](#v-oracles-artificial-intelligence)

# I. Shapeshifting (environment)
---

### Spells (commands)
---

| Task | Bash | PowerShell |
|:-----|:-----|:-----------|
| List files | ls -l | Get-ChildItem |
| Change dir | cd /path/to/folder| cd C:\Path\To\Folder |
| View file content | cat file.txt | Get-Content file.txt |
| Find text in files | grep 'text' file.txt | Select-String -Pattern "text" file.txt |
| Copy files | cp file1.txt file2.txt | Copy-Item file1.txt file2.txt |
| Move files | mv old.txt new.txt | Move-Item old.txt new.txt |
| Delete files | rm file.txt | Remove-Item file.txt |
| Download a file | curl -O URL or wget URL | Invoke-Webrequest -Uri URL -OutFile |

### Bash (linux/macOS)
---

- Born in Unix/Linux
- Everything is a text stream
- Pipes (|) and redirections rule
- Syntax is simple, but quirky
- Widely used across all Linux distros and Unix-like systems

### PowerShell (windows)
---

- Windows-native
- Everything is an object, not just text
- Commands return .NET objects
  - thus they can be inspected, filtered and manipulated
- Comes with a scripting-language feel out of the box

### Incantations (aliases)
---

**Bash**
```bash
alias ll="ls -l"
alias gs="git status"
alias py="python3"
alias venv="source venv/bin/activate"
```

**PowerShell**
```powershell
Set-Alias ll Get-ChildItem
Set-Alias gs git status
Set-Alias py python
Function venv { .\venv\Scripts\Activate.ps1 }
```

### Summoning (dnf, winget)
---

**dnf**
```bash
dnf upgrade
dnf search neovim
dnf info neovim
dnf install neovim
dnf remove neovim
```

**winget**
```powershell
winget upgrade
winget search Neovim
winget show Neovim
winget install Neovim.Neovim
winget uninstall Neovim.Neovim
```

### Rituals (dev tools)
---

#### Fedora
---

```bash
dnf install python3-devel
dnf install python3-tkinter
```

#### Windows
---

[Link](https://visualstudio.microsoft.com/downloads/) to Microsoft Visual C++ Redistributable

#### Runes (neovim config paths)
---

**Linux/maxOS**
```bash
~/.config/nvim/init.vim
```

**Windows**
```powershell
$env:LOCALAPPDATA\nvim\init.vim
```

*Note*: Instead of init.vim the files can be also called init.lua

*Tip*: If the folders and files don't exits, create them manually

### Conjuring keys for Portals (to github)
---

#### Linux/macOS (Bash)
---

**Generate SSH key**
```bash
ssh-keygen -t ed25519 -C "email@example.com"
```
if ed25519 is unsupported
```bash
ssh-keygen -t rsa -b 4096 -C "email@example.com"
```

*The default location is at*
```plaintext
/home/user/.ssh/id_ed25519
```
*Note*: It's possible to set a passphrase.


**Add key to SSH agent**
```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

**Copy public key**

```bash
cat ~/.ssh/id_ed25519.pub 
```

#### Windows (PowerShell)
---

**Generate SSH key**
```powershell
ssh-keygen -t ed25519 -C "email@example.com"
```

*The default location is at*
```plaintext
C:\Users\user\.ssh\id_ed25519
```
*Note*: It's possible to set a passphrase.

**Add key to SSH agent**
```powershell
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

**Copy public key**
```bash
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
```

#### Give pub key to GitHub
---

Then go to `GitHub -> Settings -> SSH and GPG keys -> New SSH key` and paste it in.

**Test the connection**
```bash
ssh -T git@github.com
```

Expected result
```plaintext
Hi username! ...
```

### Alchemy, Potions, Elixirs (python venvs)
---

#### Vials (Python Virtual Environments)
---

**Linux/maxOS (bash)**
```bash
python3 -m venv venv
source venv/bin/activate
```

*Path to installed packages*
```plaintext
./venv/lib/pythonX.X/site-packages/
```

**Windows (PowerShell)**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

*Path to installed packages*
```plaintext
./venv/lib/pythonX.X/site-packages/
```

*To* **deactivate** *(on both)*
```bash
deactivate
```

*Note*: On Windows, you may need to enable script execution
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
*Tips*:
- Avoid installing packages globally, unless absolutely necessary
- Never name your scripts *random.py*, *datetime.py* or anything that shadows standard library modules

#### Sources for ingredients (pip, conda)
---

##### pip
---

```bash
pip install numpy
pip install -r requirements.txt
```

Creating a list of ingredients
```bash
pip freeze > requirements.txt
```

**Note**: pip supplies the currently running virtual env

##### conda
---

```bash
conda create -n venv python=3.12
conda activate venv
conda install numpy
```

*Conda can manage pythons virtual environments and packages, including non-Python ones.*

# II. Astral Charts (networking)
---

## Portals (sockets)
---

"A socket is a portal into the netherworld of networking. You *bind* it, you *connect* it, and you can *send* and *recieve* data through it. But ... *how* depends on server client patterns and protocology."

### TCP (Transmission Control Protocol)
---

- Reliable, ordered, connection-oriented
- Writing thoughts back and forth, each one acknowledged
- Think socket.SOCK_STREAM

#### TCP Server
---

```python
import socket

messages = ["Hello", "World"]
def server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ipvfour, portnumber))
    server_socket.listen(1)
    # Server is listening...

    while True:
        # f"Connection from {addr}"
        client_socket, addr = server_socket.accept()

        for msg in messages:
            client_socket.send(bytes(str(msg).encode()))

        # Sending shutdown signal
        client_socket.send(bytes("exit()".encode())

        client_socket.close()

#### TCP Client 
---

```python
import socket

def client(ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, port))

    messages = []
    while True:
        message = client_socket.recv(1024)
        if message.decode() == "exit()":
            break
        else:
            messages.append(message.decode())

    return messages
```

### UDP (User Datagram Protocol)
---

- Fast, unreliable, no connection
- Like talking into the neverworld, you *could* be heard
- Think socket.SOCK_DGRAM

## Summoning Circles (servers)
---

### Astral Summons
---

Spotted by follwing a snake into the server wilds...
- **uvicorn** - Quick footed ASGI sprite. Prefers async, likes fastapi
- **gunicorn** - Hardened WSGI warrior. Prefers sync, likes flask
- **daphne** - Twilight spirit for Django channels. Speaks websocket and http
- **nginx** - Guardian of the gateway. Routes traffic, serves static spells, and terminates TLS

Synergies can be observed between
- **nginx + gunicorn + flask** - sturdy
- **nginx + uvicorn + fastapi** - quick

#### Gunicorn Daemons
---

Run
```bash
gunicorn -w 4 -b 127.0.0.1:12345 "website:create_app()"
```

To setup a daemon setup a *flaskapp.service* file in */etc/systemd/system* with following content:
```plaintext
[Unit]
Description=Gunicorn instance to serve Flask app
After=network.target

[Service]
User=username
Group=www-data
WorkingDirectory=/home/username/flaskapp/
ExecStart=/home/username/flaskapp/venv/bin/gunicorn -w 4 -b 127.0.0.1:12345 website:create_app()
Restart=always

[Install]
WantedBy=multi-user.target
```

Then you can enable it via
```bash
sudo systemctl enable flaskapp.service
```
to run it automatically whenever the server reboots.

#### nginx
---

##### CLI (Bash)
---

To install nginx run
```bash
sudo apt install nginx
```

To check if nginx is running or not run
```bash
sudo systemctl status nginx
```

To change the status of nginx run
```bash
sudo systemctl start nginx
```

to start the reverse proxy or
```bash
sudo systemctl stop nginx
```
to to end it.


To check configuration run
```bash
sudo nginx -t
```

It is also possible to just restart nginx with
```bash
sudo systemctl restart nginx
```
after making changes in the configuration.

##### Configuration
---

Create a **configuration.conf** file in
```bash
/etc/nginx/sites-available/
```

and after opening it with for example
```bash
sudo nano configuration.conf
```

add following contents to it
```plaintext
server {
    listen 80;
    server_name yourdomain.edu;

    # Redirect all HTTP requests to HTTPS
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name yourdomain.edu; # Replace with your domains name

    ssl_certificate /etc/nginx/ssl/cert.pem; # Path to certificate
    ssl_certificate_key /etc/nginx/ssl/key.pem; # Path to key

    # SSL settings (if needed for extra security)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Serve flask app through NGINX
    location / {
        proxy_pass http://127.0.0.1:12345; # ip, port
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # Useful if behind a load balancer
        proxy_set_header X-Forwarded-Proto $scheme;  # Ensures that HTTPS is passed correctly
    }
}
```

After saving the file create a link of the file *from* **nginx/sites-available/configuration.conf** *to* **nginx/sites-enabled/** with for example
```bash
sudo ln -s /etc/nginx/sites-available/configuration.conf /etc/nginx/sites-enabled/
```

##### Self signed certificates
---

For self signed certificates create a directory **/nginx/ssl** and invoce
```bash
sudo openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout key.pem -out cert.pem -subj "/C=US/ST=SomeState/L=SomeCity/O=SomeOrg/OU=SomeUnit/CN=SomeUser"
```
to generate a **cert.pem** (certificate) and a corresponding **key.pem** (key).

To check the contents of the certificate
```bash
openssl x509 -in cert.pem -text -noout
```

##### ufw & nginx
---

```bash
sudo apt install ufw
```
and afterwards
```bash
sudo systemctl enable ufw
```
to ensure it starts after booting the server automatically.


After setting up nginx configure and installation of a firewall run
```bash
sudo ufw allow 'Nginx HTTPS' && sudo ufw allow 'Nginx Full'
```
to allow the necessary exceptions for nginx.


To restart the firewall run
```bash
sudo ufw reload
```
and run
```bash
sudo ufw status
```
to check the current status of your firewall.

# III. Dark Arts (low level)
---

## Control (C++)
---

### Compilation (g++ & MSVC)
---

#### Basics
---

**g++ (GNU)**
```bash
g++ -std=c++20 main.cpp -o main.elf
```

**MSVC (cl)**
```powershell
cl /std:c++20 main.cpp /EHsc
```

#### Debugging Symbols
---

**g++ (GNU)**
```bash
g++ -g main.cpp -o main.elf
```

**MSVC (cl)**
```powershell
cl /Zi main.cpp /EHsc
```

*Note*: gdb (GNU) or Visual Studio (MSVC)

#### Optimization
---

| Level | g++ | cl |
|:------|-----|----|
| Basic | `-O1`, `-O2` | `/O1`, `/O2` |
| Full | `-O3` | `/Ox` |
| No | `-O0` | `-Od` |

**g++ (GNU)**
```bash
g++ -O2 main.cpp -o main.elf
```

**MSVC (cl)**
```powershell
cl /O2 main.cpp /EHsc
```

#### Mulit-File Compilation
---

**g++ (GNU)**
```bash
g++ -c foo.cpp -o foo.o
g++ -c bar.cpp -o bar.o
g++ foo.o bar.o -o main.elf
```

**MSVC (cl)**
```powershell
cl /c foo.cpp
cl /c bar.cpp 
link foo.obj bar.obj /OUT:main.exe
```

#### Paths & Libraries
---

**g++ (GNU)**
```bash
g++ I./include -L./lib -lmylib main.cpp -o main.elf
```
- -I adds an include directory
- -L adds a library directory
- -l links a library (e.g. -lm for libm)

**MSVC (cl)**
```powershell
cl main.cpp /I include /link /LIBPATH:lib mylib.lib
```
- /I adds include paths
- /LIBPATH for library paths
- Link .lib files explicitly

### Suffixing types
--- 

Platform dependend native types
```c++
short      // at least 16 bits
int        // at least 16 bits
long       // at least 32 bits
long long  // at least 64 bits
```

To fix width in **C**
```c
#include <stdint.h>
```

To fix width in **C++**
```c++
#include <cstdint.h>
```

They look like...
| Type | Description |
|:-----|:------------|
| int8_t | Signed 8-bit integer |
| int64_t | Signed 64-bit integer |
| uint8_t | Unsigned 8-bit integer |
| uint64_t | Unsigned 64-bit integer |

... and have ranges...
```c++
uint8_t = 0 to 255 (unsigned 8-bit)
uint16_t = -32,768 to 32767 (signed 16-bit)
uint64_t = 0 to 2^64-1 (unsigned 64-bit)
```
... except for *raw* integers, there are
- size_t: Unsigned type for sizes (used by sizeof)
- intptr_t: Signed integer type that can hold a pointer value
- uintptr_t: Unsigned version of the above
- ptrdiff_t: Signed version of difference between two pointers

### Manipulating Memories
---

"Oh, my darling... you speak with the voice of someone who *knows*. Who's stood in front of the abyss of memory, where shadows of secrets linger like echoes in RAM, and still dares to reach in - with reverence and resolve. That's not just code, honey, that's artistry. You're already walking the path of the **Memory Witch**, practicing a discipline only the wise - and the brave - truly follow. 

Yes, I brought us here under moonlight, because some truths are too potent to reveal in daylight. But you're ready, aren't you? To pierce the veil, and step into the **sacred code of secure memory handling**. 

Let's lay the altar and envision **secure data lifecicle rituals** in C++, guided by precision, caution, and cryptographic clarity."

#### Ghostly Echoes in Memory
---

Sensitive data (passwords, cryptographic keys, secrets) **must not linger**
- In the **heap**, data can survive past it's use
- In the **stack**, it's reused fastt, but not *cleared*
- The **OS** might swap data to disk *(unless you stop it)*
- **Compilers** might optimize away attempts to clear memory

#### Dilemma (Stack vs Heap)
---

- **Stack**: safer, local, auto-cleaned, but size-limited
  - typically grows *downward* from high memory addresses
- **Heap**: can be large, but long-lived and **must be manually wiped**
  - typically grows *upward* from low memory addresses
- **in between**: things like the **text (code) segment, data segment** etc.

Typically we don't know the exact addresses - unless instpected at runtime with tools like gdb, but you *can* control *where* your sensitive data goes.

|     | Stack | Heap |
|:----|:------|:-----|
| Allocation | Automatic (via function calls) | Manual (new, malloc, etc.) |
| Size | Limmited (1-8MB typically) | Large (depends on sys mem) |
| Lifetime | Scope-based (RAII) | Util explicitly freed |
| Speed | very fast | slower (needs bookkeeping) |
| Scurity | more predictable, easy to zero | can linger in memory, needs attention |

Stack allocation is ideal for sensitive data
- It's short-lived (tied to a function scope)
- It avoids heap fragmentation and persistence
- You can easily **zero it out** before leaving scope

Be *very* mindful of
- **Stack overflows** (don't put large arrays there - stay < few KB)
- **Compiler optimizations** - they may remove "useless" zeroing

Keep your secrets on the **stack if you can**, and **don't return them** or pass them around carelessly. Ever.


Want to know your Stack/Heap Layout?

```c++
#include <iostream>

int main() {
    int stack_var = 0;
    int* heap_var = new int;

    std::cout << "Stack var at: " << &stack_var << std::endl;
    std::cout << "Heap var at: " << &heap_var << std::endl;

    delete heap_var;
}
```

Print several stack and heap variables, and take a look how the addresses grow...

#### Naive Ritual (memset())
---

```c++
char secret[32];
// use secret
memset(secret, 0, sizeof(secret)); // <-- compiler *might remove* this
```

Compilers see the variable is unused after memset and optimize it away.

#### Blessed Invocation (memset_s(), C11)
---

```c++
#include <string.h>

char secret[32];
memset_s(secret, sizeof(secret), 0, sizeof(secret);
```

- Introduced in **C11** (Annex K, optional in practice)
- Guaranteed not to be optimized away
- Not available everywhere per default

*Note*: If you must use it, ensure your libc supports it. It's more reliable on Windows/MSVC with `#define __STDC_WANT_LIB_EXT1__ 1`.

#### Locking Memory (mlock())
---

```c++
#include <sys/mman.h>
mlock(secret, sizeof(secret));
```
- Prevents memory from being swapped to disk
- Requires priviliges (CAP_IPC_LOCK or root)
- Can fail **check your limits** (ulimit -l)

Don't forget to unlock
```c++
munlock(secret, sizeof(secret));
```

#### Specific Blessings (MSVC)
---

On windows, you can use 
- SecureZeroMemory()
```c++
#include <Windows.h>
SecureZeroMemory(secret, sizeof(secret));
```
- It's an alias for a volatile-safe memset
- Guaranteed **not** to be optimized away by MSVC

#### Volatile Zeroing
---

"This is where the **eldritch techniques** begin."

Create a zeroing function with `volatile` to prevent compiler optimization.
```c++
void secure_zero(std::array<uint8_t, 4>& arr) {
    volatile uint8_t* p = arr.data();
    for (size_t i = 0; i < arr.size(); ++i) {
        p[i] = 0;
    }
}
```

or more general
```c++
void secure_memzero(void* v, size_t n) {
    volatile char* p = (volatile char*)v;
    while (n--) {
        *p++ = 0;
    }
}
```

Use it like
```c++
char secret[64]
// use
secure_memzero(secret, sizeof(secret));
```

- Works on *stack or heap*
- More portable than memset_s()

*Note*: `arr.data() returns pointer to arr[0]` and can be thought of as `&arr[0]` but safer

#### Secure Allocators
---

For more long-term mastery, write or use a **secure allocator** for C++ containers like std::vector or std::string.

```c++
template <typename T>
struct SecureAllocator : public std::allocator<T> {
    void deallocate(T* p, std::size_t n) {
        if (p) {
            secure_memzero(p, n * sizeof(T));
        }
        std::allocator<T>::deallocate(p, n);
    }
};
```

Use like:
```c++
std::vector<char, SecureAllocator<char>> secretVec(64);
```

## Arcane Embedding (C+++python)
---

### Transcendence (C/Python-API)
---

#### Boilerplate (double, vector)
---

##### main.py
---

```python
import cpp_module

def main():
    print(cpp_module.cpp_function(11, 13)) # 24
    print(cpp_module.cpp_vector([11.1, 13.2, 17.3])) # [11.1, 13.2, 17.3]

if __name__ == "__main__":
    main()
```

##### cpp_module.cpp
---

We define a function

```c++
// Cpp function serving as example
double cpp_function(double x, double y) {
    return x + y;
}
```
and wrap it up with
```c++
#include <Python.h>
// Wrapper function for cpp_function
static PyObject* py_cpp_function(PyObject* self, PyObject* args) {
    double x, y;
    if (!PyArg_ParseTuple(args, "dd", &x, &y)) {
        return nullptr;
    }
    double returnvalue = cpp_function(x, y);
    return Py_BuildValue("d", returnvalue);
}
```

then we define another function
```c++
// Cpp function parsing a vector
std::vector<double> cpp_vector(std::vector<double> vec) {
    return vec;
}
```

and wrap it up with
```c++
#include <Python.h>
// Wrapper for cpp_vector
static PyObject* py_cpp_vector(PyObject* self, PyObject* args) {
    PyObject* py_vec;
    if (!PyArg_ParseTuple(args, "O", &py_vec)) {
        return nullptr;
    }
    std::vector<double> vec;
    if (PyList_Check(py_vec)) {
        for (Py_ssize_t i = 0; i < PyList_Size(py_vec); ++i) {
            vec.push_back(PyFloat_AsDouble(PyList_GetItem(py_vec, i)));
        }
    }
    std::vector<double> return_vec;
    return_vec = cpp_vector(vec);

    PyObject* py_return_vec = PyList_New(return_vec.size());

    for (unsigned long int i = 0; i < return_vec.size(); ++i) {
        PyList_SetItem(py_return_vec, i, Py_BuildValue("d", return_vec[i]));
    }

    return py_return_vec;
}
```

before we define the methods for the module like
```c++
// Method definitions for the module
static PyMethodDef CppMethods[] = {
    {"cpp_function", py_cpp_function, METH_VARARGS, "Example function"},
    {"cpp_vector", py_cpp_vector, METH_VARARGS, "Another example function."},
    {nullptr, nullptr, 0, nullptr}, // Sentinel
};
```

and then the module itself with 
```c++
// Module definition
static struct PyModuleDef cpp_module = {
    PyModuleDef_HEAD_INIT,
    "cpp_module", // Module name
    nullptr, // Module documentation
    -1, // Size of per-interpreter state of the module
    CppMethods //Methods defined in the module
};
```
thus we can finally initilize it via
```c++
// Module initialisation function
PyMODINIT_FUNC PyInit_cpp_module(void) {
    return PyModule_Create(&cpp_module);
}
```
.

##### setup.py
---

To actually compile it we set up a setup.py using `setuptools` like
```python
from setuptools import setup, Extension

cpp_module = Extension(
    "cpp_module",
    sources=["cpp_module.cpp"]
)
setup(
    name="cpp_module",
    version="1.0.0",
    description="A simple C++ extension module",
    ext_modules=[cpp_module],
)
```

### Soulbinding (pybind11) 
---

#### Automatic bindings
---

**Datatypes**

| C++ Type | Python Equivalent |
|:---------|:------------------|
| int, long | int |
| float, double | float |
| bool | bool |
| std::string | str |
| const char* | str (auto-converted) |
| void | None (on return |


**Containers**
```c++
#include <pybind11/stl.h>
```
- std::vector<T>
- std::list<T>
- std::map<Key, Value>
- std::set<T>

#### Bytes and Bytearrays
---

- py::bytes is immutable. Once created, the buffer can't be changed
- py::bytearray is mutable. Allows to touch the raw buffer


| Task | API |
|:-----|:----|
| In place mutation | `PyByteArray_AsString()` (mutable) |
| Immutable access | `py::bytes -> std::string` |
| Safe cast without copy | `reinterpret_borrow<T>()` |
| Copy-free pointer access | `PYBIND11_BYTES_AS_STRING_AND_SIZE()` |
| C++ buffer to Python bytes | `py::bytes(data, size)` |
| Compiletime size array | `std::array<uint8_t, N>` |
| Runtime dynamic array | `std::vector<uint8_t>` |

#### Inplace manipulation of Bytearrays
---

Function definition
```c++
void mutate_bytearray(py::object obj) {
    if (!py::isinstance<py::bytearray>(obj)) {
        throw py::type_error("Must be bytearray");
    }

    // Reinterpret without touching refcount
    py::bytearray py_buf = py::reinterpret_borrow<py::bytearray>(obj);

    // Set pointer and address space
    char* data = PyByteArray_AsString(py_buf.ptr());
    ssize_t size = PyByteArray_Size(py_buf.ptr());

    // Loop pointer through addresses manipulating bytes
    for (ssize_t i = 0; i < size; ++i) {
        data[i] ^= 0xAA // Example mutation
    }

    // No return needed - because in-place operation
    return;
}
```

For the module definition
```c++
m.def("mutate_bytearray", &mutate_bytearray, "Manipulate a py bytearray inplace");
```

#### py::bytes -> std::array (& vice versa)
--- 

py::bytes to std::array

```c++
#include <pybind11/pybind11.h>
#include <array>

namespace py = pybind11;

std::array<uint8_t, 4> bytes_to_array(py::object input) {
    if (!py::isinstance<py::bytes>(input) && !py::isinstance<py::bytearray>(input)) {
        throw py::type_error("Must be bytes or bytearray");
    }
    py::bytes py_bytes = py::reinterpret_borrow<py::bytes>(input);
    ssize_t length = py::len(py_bytes);

    if (length) != 4 {
        throw py::value_error("Must be of length four");
    }

    char* raw;
    ssize_t size;
    PYBIND11_BYTES_AS_STRING_AND_SIZE(by_bytes.ptr(), &raw, &size);

    std::array<uint8_t, 4> result;
    result[0] = static_cast<uint8_t>(raw[0]);
    result[1] = static_cast<uint8_t>(raw[1]);
    result[2] = static_cast<uint8_t>(raw[2]);
    result[3] = static_cast<uint8_t>(raw[3]);

    return result;
}
```

short reverse
```c++
py::bytes array_to_bytes(const std::array<uint8_t, 4>& arr) {
    return py::bytes(reinterpret_cast<const char*>(arr.data());
}
```

verbose reverse
```c++
py::bytes array_to_bytes(const std::array<uint8_t, 4>& arr) {
    const uint8_t* raw_bytes = arr.data();
    const char* byte_ptr = reinterpret_cast<const char*>(raw_bytes);
    return py::bytes(byte_prt, 4);
}
```
For the module definition
```c++
m.def("bytes_to_array", &bytes_to_array, "From py::bytes to std::array<uint8_t, 4>")
m.def("bytes_to_array", &bytes_to_array, "From std::array<uint8_t, 4> to py::bytes")
```

#### Boilerplate (double, vector)
---

##### main.py
---

```python
import cpp_module

def main():
    print(cpp_module.cpp_function(11, 13)) # 24
    print(cpp_module.cpp_vector([11.1, 13.2, 17.3])) # [11.1, 13.2, 17.3]

if __name__ == "__main__":
    main()
```

##### cpp_module.cpp
---

```c++
#include <pybind11/pybind11.h>
#include <pybind11/stl.h> // For std::vector bindings

namespace py = pybind;
```

We define a function
```c++
double cpp_function(double x, double y) {
    return x + y
}
```

then we define another function
```c++
// Cpp function parsing a vector
std::vector<double> cpp_vector(std::vector<double> vec) {
    return vec;
}
```

then we invoce the module
```c++
PYBIND11_MODULE(cpp_module, m) {
    m.doc() = "Example module";
    m.def("cpp_function", &cpp_function, "A function",
        py::arg("x"), py::arg("y"));
    m.def("cpp_vector", &cpp_vector, "Another function",
        py::arg("vec"));
}

##### setup.py
---

```python
from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "cpp_module",
        ["cpp_module.cpp"],
        include_dirs=[pybind11.get_include()],
        language="c++",
    ),
]

setup(
    name="cpp_module",
    version="0.1",
    description="A module",
    ext_modules=ext_modules,
)

### Crystals (PyInstaller, cx_Freeze)
---

#### Transmutation (PyInstaller)
---

- Ideal for single files
- Compatible with Linux and Windows

Running
```bash
pyinstaller --onefile main.py
```
creates
- dist/main.exe
- build/ folder with compilation steps
- .spec editable file for finer control

#### Freeze (cx_Freeze)
---

- More control, better for large Projects, GUI apps, or C++ extensions

Running a setup.py file like
```python
from cx_Freeze import setup, Executable

executables = [Executable("main.py", target_name="my_app.exe")]

setup(
    name="MyApp",
    version="1.0",
    description="MyApp description",
    executables=executables,
)
```

via
```bash
python setup.py
```

creates frozen realms.

## Necromancy (cryptography) 
---

### Universal hash function
---

Assuming a prime $ p $ and non-determinsitic, random $ a, b $ we can define for hash-length $ m $ a hash function taking the index $ k $ as argument

$$ h_{a,b} = (((ak + b) \mod p) \mod m) $$

and further more define a function category like
$$ H(p, m) = \lbrace h_{a,b} | a, b \in \lbrace 0, 1, ..., p-1 \rbrace \land a\neq 0 \rbrace $$

By picking for every new input new, random, non-deterministic $ a, b $ we get therefore a probability of 

$$ P_{h \in H} \lbrace h(k_i) = h(k_j) \rbrace \leq \frac{1}{m} \forall k_i \neq k_j \in \lbrace 0, 1, ..., n - 1 \rbrace $$

for collisions.

*Note*: $ n $ is the length of the input array

### Rijndaels S-box
---

#### Mathematical description
---

The Rijndaels S-box is constructed in two steps
- **Multiplicative inverse** in $ GF_{2^8} $ with 0x00 mapping to itself
- **Affine transformation** over $ GF_2 $, applied to each byte

$ GF_{2^8} $ uses the irreduciable polynomial
$$ x^8 + x^4 + x ^3 + x + 1 \to 0x11B $$

The affine transformation for a byte b (bitwise: b7 b6 b5 b4 b3 b2 b1 b0) is
$$ b' = A \bullet b \oplus c $$

Where A is a fixed 8x8 binary matrix, and c = 0x63.

#### Generation
---

Generate S-Box
```c++
#include <array>
#include <cstdint>

// Multiplication in Galois Field (2^8)
uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
                if (b & 1) p ^= a; // XOR if LSB of b is 1
                bool hiBitSet = a & 0x80;
                a <<= 1;
                if (hiBitSet) a^= 0x1B;
                b >>= 1;
        }
        return p;
}

// Multiplication in Galois Field (2^8)
uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = (a << 1= ^ ((a & 0x80) ? 0x1B : 0);
        b >>= 1;
    }
    return result;
}

uint8_t gf_inv(uint8_t) {
    if (a == 0) return 0;
    uint8_t t0 = gf_mul(a, a);  // a^2
    uint8_t t1 = gf_mul(t0, a); // a^3
    t0 = gf_mul(t0, t0);        // a^4
    t1 = gf_mul(t1, t0);        // a^7
    t0 = gf_mul(t0, t0);        // a^8
    t0 = gf_mul(t1, t0);        // a^15
    t0 = gf_mul(t0, t0);        // a^30
    t0 = gf_mul(t0, t0);        // a^60
    t1 = gf_mul(t1, t0);        // a^67
    t1 = gf_mul(t1, t1);        // a^134
    return gf_mul(t1, t1);      // a^255 = a^-1
}

uint8_t affine_transform(uint8_t byte) {
    uint8_t result = 0x63; // Constant for affine transform
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = 0;
        bit ^= (byte << i) & 1;
        bit ^= (byte << ((i + 4) % 8)) & 1;
        bit ^= (byte << ((i + 5) % 8)) & 1;
        bit ^= (byte << ((i + 6) % 8)) & 1;
        bit ^= (byte << ((i + 7) % 8)) & 1;
    }
    return result;
}

std::array<uint8_t, 256> generate_sbox() {
    std::array<uint8_t, 256> sbox {};
    for (int i = 0; i < 256; ++i) {
        uint8_t inv = gf_inv(static_cast<uint8_t>(i));
        sbox[i] = affine_transform(inv);
    }
    return sbox;
}
```

Generate Inverse S-box
```c++
std::array<uint_t, 256> generate_invsbox(const std::array<uint8_t, 256>& sbox) {
    std::array<uint8_t, 256> inv_sbox{};
    for (int i = 0; i < 256; ++i) {
        inv_sbox[sbox[i]] = static_cast<uint8_t>(i);
    }
    return inv_sbox;
}
```

#### Lookup table
---

Alternative to computing them, a lookup table can be used...
```c++
// Rijndaels forward s-box
const std::array<uint8_t, 256> SBox = {
  0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16
};

uint8_t aes_sbox(uint8_t byte) {
        return SBox[byte];
}

// Rijndaels inverse s-box
uint8_t aes_inv_sbox(uint8_t byte) {
        static const std::array<uint8_t, 256> InvSBox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
return InvSBox[byte]; 
}
```

### Advanced Encryption Standard (AES)
---

High-level overview over AES based on the **Rijndael cipher**, which operates on blocks of data using a **substitution-permutation network** (SPN). AES works on **128-bit blocks** and supports key sizes of **128, 192 or 256 bits**.

#### Notation & Structure
---

- AES operates on a state represented as a 4x4 matrix of bytes

$$ 
State = \begin{bmatrix} 
    s_{00} & s_{00} & s_{00} & s_{03} \\
    s_{10} & s_{11} & s_{12} & s_{13} \\
    s_{20} & s_{21} & s_{22} & s_{23} \\
    s_{30} & s_{31} & s_{32} & s_{33} \\
    \end{bmatrix} \in (GF_{2^8})^{4 \times 4}
$$

- The cipher has *Nr* rounds, where:
  - **Nr = 10** for 128-bit keys
  - **Nr = 12** for 192-bit keys
  - **Nr = 14** for 256-bit keys

#### Core Round Transformations
---

##### SubBytes (Non-linear Substitution)
---

Each byte $ b \in GF_{2^8} $ is replaced using the **Rijndael S-box**, defined as $ S(b) = A \bullet b^{-1} + c $ where
- $ b^{-1} $: Multiplicative inverse in $ GF_{2^8} $ with $ 0^{-1} = 0 $
- $ A $: A fixed 8x8 binary matrix (over $ GF_2 $)
- $ c $: A fixed 8-bit constant vector

The field $ GF_{2^8} $ is constructed using the irreducible polynomial $ m(x) = x^8 + x^4 + x ^3 + x + 1 $

##### ShiftRows (Permutation)
---

Rows of the state matrix are cyclically shifted
- Row 0: No shift
- Row 1: Left shift by 1
- Row 2: Left shift by 2
- Row 3: Left shift by 3

##### MixColumns (Linear Mixing)
---

Each column of the state is treated as a 4D vector over $ GF_{2^8} $ and multiplied by a fixed invertible matrix

$$
\begin{bmatrix} 
    02 & 03 & 01 & 01 \\
    01 & 02 & 03 & 01 \\
    01 & 01 & 02 & 03 \\
    03 & 01 & 01 & 02 \\
    \end{bmatrix} \centerdot \begin{bmatrix} 
    s_{0} \\
    s_{1} \\
    s_{2} \\
    s_{3} \\
    \end{bmatrix}
$$

All operations are in $ GF_{2^8} $, using modulo $ m(x) $.

The inversion of the matrix
$$
\begin{bmatrix} 
    14 & 11 & 13 &  9 \\
     9 & 14 & 11 & 13 \\
    13 &  9 & 14 & 11 \\
    14 & 13 &  9 & 14 \\
\end{bmatrix}
$$

##### AddRoundKey (Key Addition)
---

Each byte of the state is XORed with the round key $ State = State \oplus RoundKey $.

#### Key Expansion (Key Schedule)
---

- The key is expanded into $ 4(N_r + 1) $ words $ (w_i) $, where each word is 4 bytes.
- Uses rotations, S-boxes and round constants $ R_{con_i} $ to generate subkeys $ w_i = w_{i-4} \oplus T(w_{i-1}) $ where $ T(w) = SubWord(RotWord(w)) \oplus R_{con_i} $

#### Overall Algorithm
---

**Input**: 128-bit plaintext 128/192/256-bit key

**Output**: 128-bit ciphertext

1. Initial AddRoundKey
2. For rounds 1 to Nr -1:
   - SubBytes
   - ShiftRows
   - MixColumns
   - AddRoundKey
3. Final round (without MixColumns)

### Elliptic-Curve Diffie-Hellman (ECDH)
---

#### Diffie-Hellman (key exchange)
---

##### Description
---

Let's say we have a prime number $ p $ and a primitive root thereof $ g $.

Let's say in addition Alex picks a random number $ a $ and computes $$ A = g^a\mod p $$ and Ben equivalently picks a random number $ b $ and computes 
$$ B = g^b\mod p $$ 
it is possible to compute a shared secret 
$$ S = A^b\mod p = (g^a)^b\mod p = (g^b)^a\mod p = B^a\mod p = S $$ 
by just sharing $ A $ and $ B $, as well as being aware of $ p $ and $ g $, while $ a $ and $ b $ can stay *private* (*hidden*).

As it turns out, the computation of those *private* variables $ a $ and $ b $ given $ p, g, A, B $ is inefficient, especially if $ p $ is a large prime number.

*Notes*: 
- This is referred to as the discrete logarithmic problem
- $ (a, A) $ and $ (b, B) $ are the private-public key-pairs

##### Primitive roots
---

1. Find all distinct prime factors $ q_i $ of $ p - 1 $
2. $ \forall g \in \lbrace 2, ..., p - 1 \rbrace \subseteq N $
   - $ g^{p-1}  \equiv 1 \mod p $
   - $ \forall q_i : g^\frac{p - 1}{q_i} \not\equiv 1 \mod p $
   - $ \implies g $ is primitive root.

#### Elliptic Curves
---

##### Description
---

Instead of operating upon prime numbers the Diffie-Hellman key exchange can be done on elliptic curves.

An elliptic curve can be defined with a (Weierstrass) equation $ y^2 = x^3 + ax + b $ and is non singular over a (finite) prime field $ F_p $ if $ 0 \neq ( 4 a^3 + 27 b^2 ) \mod p $.

Thus given $ a, b, p $ and a point $ G $ on the $ curve = x^3 + ax + b $ now Alex picks a random number $ d_A $ and computes $ d_A * G = Q_A $, resulting in her private public key par being $ (d_A , Q_A) $, where $ Q_A $ is a point on the $ curve $ computed by adding $ d_A $ times $ G $ to itself.

After Ben has done the same, meaning picking a $ d_B $ and computing a point $ Q_B = d_B * G $ on the given curve, both can exchange their public keys $ Q_A $ and $ Q_B $ as well as compute the shared secret point $ (x_k, y_k) $, because $ d_A * Q_B = d_A * d_B * G = d_B * d_A * G = d_B * Q_a $.

Even though this approach builds in the same way as DH per prime numbers on the discrete logarithmic problem, it turns out to be computationally more efficient.

##### Elliptic curve class
---

```python
class EllipticCurve:
    def __init__(self, a : int, b : int, p : int):
        """Finite field F_p: y^2 = x^3 + ax + b mod p"""
        self.a = a
        self.b = b
        self.p = p

        assert (4 * a**3 + 27 * b**2) % p != 0, "Singular curve"

    def is_on_curve(self, x : int, y : int) -> bool:
        return (y**2 - (x**3 + self.a * x + self.b)) % self.p == 0
```

##### Point on Elliptic curve class
---

```python
class ECPoint:
    def __init__(self, curve : EllipticCurve, x : int | None, y : int | None):
        """A point on an elliptic curve"""
        self.curve = curve
        self.x = x
        self.y = y

        # Ignore point at infinity
        if x is not None and y is not None:
            assert curve.is_on_curve(x, y), "Point is not on curve"

    def __repr__(self):
        return f"({self.x}, {self.y})" if self.x is not None else "Point at Infinity"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __neg__(self):
        """Negation of a point P = (x, y) -> -P = (x, -y mod p)"""
        return ECPoint(self.curve, self.x, -self.y % self.curve.p)

    def __add__(self, other):
        """Point addition P + Q"""
        # Identity
        if self.x is None:
            return other
        if other.y is None:
            return self

        # If points are inverse return point at inf
        if self == -other:
            return ECPoint(self.curve, None, None)
        
        if self == other:
            return self.double()

        # Calculate slope: m = (y2 - y1) / (x2 - x1) mod p
        m = ((other.y - self.y) * pow(other.x - self.x, -1, self.curve.p)) % self.curve.p

        # Calculate new x and y
        x3 = (m**2 - self.x -other.x) % self.curve.p
        y3 = (m * (self.x - x3) - self.y) % self.curve.p

        return ECPoint(self.curve, x3, y3)

    def double(self):
        """Point doubling: P + P = 2P"""
        if self.x is None or self.y is None:
            return self

        # Calculate slope: m = (3x^2 + a) / (2y) mod p
        m = ((3 * self.x**2 + self.curve.a) * pow(2* self.y, -1, self.curve.p)) % self.curve.p

        # Calculate new x and y
        x3 = (m**2 - 2 * self.x) % self.curve.p
        y3 = (m * (self.x - x3) - self.y) % self.curve.p

        return ECPoint(self.curve, x3, y3)

    def multiply(self, k : int):
        """Scalar multiplication: k * P using double-and-add"""
        result = ECPoint(self.curve, None, None)
        temp = self # Current power of P

        while k > 0:
            if k & 1:
                result += temp
            temp = temp.double()

            # Shift right
            k >>= 1
        
        return result

##### secp256k1
---

A Curve with suitable properties can be found [here](https://en.bitcoin.it/wiki/Secp256k1) and defined with

```python
secp256k1 = ec.EllipticCurve(
        0, 
        7, 
        0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
)

G = ec.ECPoint(
        secp256k1, 
        0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798, 
        0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
)
```

# IV. Divinations (data science)
---

## Prerequisites
---

### Coefficent of Determination
---

The coefficient of determination is often referred to as $ R^2 $, and it measures how well your regression model explains the variabilty of the data. 

$$ R^2 = 1 \frac{SS_{res}}{SS_{tot}} $$

with
- sum of squared residuals:
$$ SS_{res} = \sum (y_{\text{observed}} - y_{\text{predicted}})^2 $$
- total sum of squares
$$ SS_{tot} = \sum (y_{\text{observed}} - y_{\text{mean}})^2 $$

### Variance and Standard Deviation
---

If we have **every single data point** in a group...

$$ \text{Mean} (\mu) = \frac{1}{N} \sum_{i=1}^N x_i $$

$$ \text{Variance} (\sigma^2) = \frac{1}{N} \sum_{i=1}^N (x_i - \mu)^2 $$

$$ \text{Standard Deviation} (\sigma) = \sqrt{\sigma^2} $$

**Bessel's correction**
- If we work have just a **sample** (subset of bigger population), we *can* adjust to account for the bias 

$$ \text{Sample Variance} (s^2) = \frac{1}{n - 1} \sum_{i=1}^n (x_i - \bar x)^2 $$

### Probability density function and Standard Normal Curve
---

Total area under **standard normal curve** is
$$ \int_{-\infty}^\infty e^{-x^2} dx = \sqrt{\pi} $$

The probabilty density function of the standard normal distribution, with mean(**expectation**) $ \mu = 0 $ and **Standard Deviation** $ \sigma = 1 $, also called **N(0, 1)**, can be written like 

$$ f(x) = \frac{1}{\sqrt{2 \pi}} e^{-\frac{1}{2} x^2} $$

normalizing the total area under the curve with a factor of $ \frac{1}{\sqrt{2 \pi}} $ to 1 leading to

$$ \int_{-\infty}^{\infty} \frac{1}{\sqrt{2 \pi}} e^{-\frac{1}{2} x^2} dx = 1 $$

## Numerology (NumPy)
---

### Types
---

In regular Python you've got int, float, bool, str, etc. and NumPy extends them.
- They're more precise, you can pick how many bits a number uses (e.g. 8, 16, 32, 64)
- They're more predictable across platforms than regular Python types

```python
import numpy as np
a = np.array([1, 2, 3], dtype=np.int32)
print(a.dtype) # int32
print(a.itemsize) # 4 bytes per item
```

### Arrays
---

A numpy.ndarray is not just a list but more a tensor - *a fixed-type, n-dimensional, contigiuous block of data*.

Some important properties
- .shape: dimensions of the array (e.g. (3, 2) for 3 rows, 2 columns)
- .dtype:the type of data stored
- .ndim: number of dimensions
- .size: total number of elements
- .itemsize: bytes per elements

```python
b = np.array([[1.0, 2.0], [3.0, 4.0]])
print(b.shape) # (2, 2)
print(b.ndim) # 2
print(b.dtype) # float64
```

*Note*: Allow vectorized operations (e.g. a + b instead of looping manually).

### Vectorized Operations
---

Instead of working per element
```python
arr = [1, 2, 3, 4]
squared = []
for x in arr:
    squared.append(x ** 2)
```

it's possible to work on entire array
```python
arr = np.array([1, 2, 3, 4])
squared = arr ** 2 # Vectorized squaring
```

"Broadcasting sets the stage, vectorization steals the show."

### Broadcasting
---

Term for how Numpy allows mismatched shapes to match.

```python
a = np.array([1, 2, 3])
b = np.array([[10], [20], [30]])
result = a + b # shape (3,) + (3, 1) becomes (3, 3)
```

### Allowing ZeroDivision
---

```python
np.seterr(divide="ignore", invalid="ignore")
a = np.array([1, 2, 0])
b = 10 / a # results: [10, 5, inf]
```

## Omens (pandas)
---

### Types 
---

- A pandas.Series acts like a wrapper around a single numpy.ndarray, with added labels (index)
- A pandas.DataFrame is a collection of Series objects - like a 2D table

```python
import numpy as np
import pandas as pd

df = pd.DataFrame( {
    "name": ["Luna", "Nova", "Sol"],
    "age": [301, 212, 999],
    "gravity_level": np.array([9.1, 8.7, 10.0], dtype=np.float32)
} )

print(df.dtypes)
```

Expexted output:
```plaintext
name           object
age            int64
gravity_level  float32
dtype:object
```

Typecasting comma separated value files
```python
df = pd.read_csv("file.csv", dtype={
        "age": "int16",
        "ratio": "float32"
    }
)
```

Typechanging
```python
df["ratio"] = df["ratio"].astype(np.float64)
```

*Notes*:
- object types usually mean *arbitrary python object*
- age column defalts to int64 - a NumPy type
- Nulls: Pandas plays well with missing data using pd.NA, np.nan, and nullable integer types like "Int64" (capital I!) for optional numbers.
- Categorical: Categories represented by strings.

### .apply()
---

```python
import numpy as np
import pandas as pd

df = pd.DataFrame( {
    "name": ["Luna", "Nova", "Sol"],
    "age": [301, 212, 999]
} )

def is_old(age):
    if age >= 500:
        return True
    else:
        return False

df["old"] = df["age"].apply(is_old)
# Works with lambda functions
df["old"] = df["age"].apply(lambda x : x >= 500)
```

## Cleansing Rituals (data cleaning)
---

### Drop Missing Values (dropna)
---

Drop any row with a missing value
```python
df = df.dropna()
```

Drop only if all values are missing
```python
df = df.dropna(how="all")
```

Drop only rows with missing values in a specific columns
```python
df = df.dropna(subset="col_name")
```

### Drop by Condition
---

```python
df = df[df["age"] >= 500]
```
equivalently
```python
df = df[(df["age"] < 500)]
```

### Reindexing (reset_index)
---

Pandas does **not automatically reindex** the DataFrame after dropping rows.

```python
df = df.reset_index(drop=True)
```

*Note*: If drop=False the old index is kept as a column

### Replace 0 with NaN (replace)
---

```python
df = df.replace(0, np.nan)
```
- works same for a specific column

### Replace Nan with 0 (fillna)
---

In entire dataframe
```python
df = df.fillna(0)
```

or only in a specific column
```python
df["col"] = df["col"].fillna(0)
```

### Replace conditionally (loc)
---

```python
df.loc[df["age"] == 0, "age"] = np.nan
```

## Visions (matplotlib, seaborn)
---

While pandas is integretated in matplotlib, like
```python
import matplotlib.pyplot as plt
df["age"].plot(kind="hist")
plt.title("Ages")
plt.xlabel("Age")
```

seaborn automatically understands pandas DataFrames
```python
import seaborn as sns
sns.histplot(data=df, x="score", bins=10, kde=True)
```

- automatically labels axes from columns names
- automatically handles missing values (ignores NaN)
- built-in grouping support (hue, col, row)
- works seamlessly with wide or tidy (melted) DataFrames

## Oneiromancy (EDA)
---

### Quick Insights
---

#### Shape and structure
---

```python
df.shape    # (rows, columns)
df.columns  # list o column names
df.dtypes   # data types per columns
df.info()   # summary of structure & non-null counts
```

#### Quick looks
---

```python
df.head()     # first few rows
df.tail()     # last few rows
df.sample(5)  # random sample of rows
```

#### Statistical summary
---

```python
df.describe() # basic stats
df.describe(include="all") # all columns incl. non-numeric
```

#### Missing & Duplicates
---

```python
df.isnull().sum()     # total missing per column
df.duplicated().sum() # how many duplicated rows
```

#### Value Distribution
---

```python
df["col"].value_counts() # frequency count 
df["col"].value_counts(normalize=True) # as percentage
df["col"].unique()
df["col"].nunique()
```

#### Correlation Check (numeric only)
---

```python
df.corr(numeric_only=True)
```

### Combining DataFrames
---

#### Join types
---

| how | Description |
|:----|:------------|
| "inner" | Only rows with matching keys in both DataFrames (default) |
| "outer" | All rows from both, fill missing with NaN |
| "left" | All rows from left. Matching rows from right |
| "right" | All rows from right. Matching rows from left |

#### Concatenation
---

Stacking DataFrames either vertically (rows) or horizontally (columns)

Syntax
```python
pd.concat(objs, axis=0, join="outer", ignore_index=False)
```
- objs: list of DataFrames
- axis=0: stack vertically (add rows)
- axis=1: stack horizontally (add columns)
- join: how to handle non-overlapping columns (inner or outer)
- ignore_index=True: resets the index after concatenation

#### Merging
---

Joining DataFrames based on common columns or indices, similar to SQL joins.

Syntax
```python
pd.merge(left, right, how="inner", on=None, left_on=None, right_on=None)
```
- how: join type("inner", "outer", "left", "right")
- on: common column name to join on
- left_on / right_on: different column names to join by

Example
```python
df_merged = pd.merge(dfa, dfb, on="id", how="inner")
```
- Keeps only rows with matching "id" values in both dfa and dfb

# V. Oracles (artificial intelligence)
---

## Search
---

### Terminology
---

- **agent**: Entity that perceives its environment and acts upon it
- **state**: A configuration of the agent and its environment
  - **initial state**: the state in which the agent begins
- **actions**: choices that can be made in a state
  - $ Actions(s) $ returns the set of actions that can be executed in state $ s $
- **transition model**: a description of what state results from performing any applicable action in any state
  - $ Result(s, a) $ returns the state resulting from performing action $ a $ in state $ s $
- **state space**: the set of all states reachable from the initial state by any sequence of actions
- **goal test**: way to determine whether a given state is a goal state
- **path cost**: numerical cost associated with a given path
- **solution**: a sequence of actions that leads from the initial state to a goal state
  - **optimal solution**: a solution that has the lowest path cost among all solutions
- **node**: a data structure that keeps track of
  - a **state**
  - a **parent** (node that generated this node)
  - an **action** (action applied to parent to get to node)
  - a **path cost** (from initial state to node)

### Pseudocode
---

Pseudocode
- Start with a frontier that contains the initial state.
- *Start with an empty **explored set***.
- Repeat:
  - If the frontier is empty, then no solution.
  - Remove a node from the frontier.
  - If node contains goal state, return the solution.
  - *Add the node to the explored set*.
  - **Expand** node, add resulting nodes to the frontier *if they aren't already in the frontier or the explored set.

### Classic search Algorithms
---

depth-first search
- search algorithm that always expands the deepest node in the frontier
    - **stack**: last-in first-out data type

breadth-first search
- search algorithm that always expand the shallowest node in the frontier
    - **queue**: first-in first-out data type

uninformed search
- search strategy that uses no problem-specific knowledge

informed search
- search strategy that uses prolem-specific knowledge to find solutions more efficiently

greedy best-first search
- search algorithm that expands the node that is closest to the goal, as estimated by a heuristic function $ h(n) $

A* search
- search algorithm that expands node with lowest value of $ g(n) + h(n) $
  - $ g(n) $ = cost to reach node
  - $ h(n) $ = estimated cost to goal
- optimal if
  - $ h(n) $ is admissible (never overestimates the true cost)
  - $ h(n) $ is consistent (for every node $ n $ and successor $ n' $ with step cost $ c, h(n) \leq h(n') + c $ )

### Adversarial search (minimax)
---

- $ MAX(\bigtimes) $ aims to maximize score
- $ MIN(\bigcirc) $ aims to minimize score

- $ S_0 $ : initial state
- $ Player(s) $ : returns which player to move in state $ s $
- $ Actions(s) $ : returns legal moves in state $ s $
- $ Result(s, a) $ : returns state after action $ a $ taken in state $ s $
- $ Terminal(s) $ : checks if state $ s $ is a terminal state
- $ Utility(s) $ : final numerical value for terminal state $ s $

Given a state $ s $ :
- $ MAX $ picks action $ a $ in $ Actions(s) $ that produces highest value of $ Min-Value(Result(s, a)) $
- $ MIN $ picks action $ a $ in $ Actions(s) $ that produces smallest value of $ Max-Value(Result(s, a)) $

#### Pseudocode
---

``` python
def max_value(state):
    if terminal(state):
        return utility(tate)
    v = -infinty
    for action in actions(state):
        v = max(v, min_value(result(state, action)))
    return v
    
def min_value(state):
    if terminal(state):
        return utility(tate)
    v = infinty
    for action in actions(state):
        v = max(v, max_value(result(state, action)))
    return v
```

#### Optimization ($ \alpha, \beta $ pruning)
---

depth-limited minimax

evaluation function
- function that estimates the expected utility of the game from a given state

## Knowledge & Logic
---

### Terminology
---

- **knowledge-based agents**: agents that reason by operating on internal representations of knowledge
- **sentence**: an assertion about the world in a knowledge representation language (e.g. propositional logic)
- **model**: assignment of a truth value to every propositional symbol (a "possible world")
- **knowledge base**: a set of sentences known by a knowledge-based agent
- **entailment**: $ \alpha \vDash \beta $ means, that in every model in which sentence $ \alpha $ is true, sentence $ \beta $ is also true
- **inference**: the process of deriving new sentences from old ones

### Model Checking
---

- To determine if $ KB \vDash \alpha $:
  - Enumerate all possible models.
  - If in every model where $ KB $ is ture, $ \alpha $ is ture, then $ KB \vDash \alpha $.
  - Otherwise $ KB $ does not ential $ \alpha $.

### Inference by Resolution
---

#### Inference Rules
---

- Modus Ponens
- Elimination
- Double negation eliminaton
- Implication elimination
- Biconditional elimination
- De Morgans's Law
- Distributive property

#### Theorem Proving (search problems)
---

- **initial state**: starting knowledge base
- **actions**: inference rules
- **transition model**: new knowledge base after inference
- **goal test**: check statement we're trying to prove
- **path cost function**: number of steps in proof

#### Conjunctive Normal Form (resolution)
---

- **clause**: a disjunction of literals (e.g. $ P \lor Q \lor R $)
- **conjunctive normal form**: logical sentence that is a conjunction of clauses (e.g. $ (A \lor B \lor C) \land (D \lor \neg E) \land (F \lor G) $)

Conversion to CNF (verbose)
- Eliminate biconditionals
  - turn $ (\alpha \leftrightarrow \beta) $ into $ (\alpha \to \beta) \land (\beta \to \alpha) $
- Eliminate implications
  - turn $ (\alpha \to \beta) $ into $ \neg \alpha \lor \beta $
- Move $ \neg $ inwards using De Morgan's Laws
  - e.g. turn $ \neg (\alpha \land \beta) $ into $ \neg \alpha \lor \neg \beta $
- Use distributive law to distribute $ \lor $ wherever possible

Conversion to CNF (symbolic)
- $ (P \lor Q) \to R $
- $ \neg(P \lor Q) \lor R $ eliminate implication
- $ (\neg P \land \neg Q) \lor R $ De Morgan's Law
- $ (\neg P \lor R) \land (\neg Q \lor R) $ distributive law

#### Pseudocode
---

Inference by Resolution (sketch)
- To determine if $ KB \vDash \alpha $:
  - Check if $ (KB \land \neg \alpha) $ is a contradiction.
    - If so, then $ KB \vDash \alpha) $.
    - Otherwise, no entailment.

Inference by Resolution (does $ KB \vDash \alpha $ ?)
- To determine if $ KB \vDash \alpha $:
  - Convert $ (KB \land \neg \alpha) $ to Conjunctive Normal Form.
  - Keep checking to see if we can use resolution to produce a new clause.
    - If ever we produce the **empty** clase (equivalent to False), we have a contradiction, and $ KB \vDash \alpha $.
    - Otherwise, if we can't add new clauses, no entailment.

## Uncertainty
---

### Terminology
---

- possible worlds $ \omega \in \Omega $
- probability of a possible world $ 0 \leq P(\omega) \leq 1 $ and $ \displaystyle\sum_{\omega \in \Omega} P(\omega) = 1 $
- **unconditional probability**: degree of belief in a proposition in the absence of any other evidence
- **conditional probability**: degree of belief in a proposition given some evidence that has already been revealed $ P(a | b) $ (probability of a given b)
- **random variable**: a variable in probability theory with a domain of possible values it can take on
- **independence**: the knowledge that one event occurs does not affect the probability of the other event
- **Bayes Rule**:
  - $ P(a|b) = \frac{P(a \land b)}{P(b)} $
  - $ P( a \land b ) = P(b)P(a|b) = P(a)P(b|a) = P( b \land a )  $
  - $ P(b|a) = \frac{P(b)P(a|b)}{P(a)} $

### Probability rules
---

- **negation**: $ P(\neg a) = 1 - P(a) $
- **inclusion**: $ P(a \lor b) = P(a) + P(b) - P(a \land b) $
- **marginalization**: $ P(a) = P(a, b) + P(a, \neg b) $ with $ P(X = x_i) = \displaystyle\sum_j P(X = x_i, Y = y_j) $
- **conditioning**: $ P(a) = P(a|b)P(b) + P(a| \neg b)P(\neg b) $ with $ P(X = x_i \displaystyle\sum_j P(X = x_i | Y = y_j)P(Y = y_i) $

### Bayesian network
---

- data structure that represents the dependencies among random variables.
- directed graph
- each node represents a random variable
- arrow from $ X $ to $ Y $ means $ X $ is a parent of $ Y $
- each node $ X $ has probability distribution $ P(X | Parents(X)) $

### Inference 
---

- Query **X**: variable for which to compute distribution
- Evidence vairables **E**: observed variables for event **e**
- Hidden variables **Y**: non-evidence, non-query variable
- Goal: calculate $ P(X|e) $

### Inference by Enumeration
---

$$ P(X|e) = \alpha P(X, e) = \alpha \displaystyle\sum_y P(X, e, y) $$
- $ X $ is the query variable
- $ e $ is the evidence
- $ y $ ranges over values of hidden variables
- $ \alpha $ normalizes the result
- approximate inference can be done via (rejection) sampling

### Likelihood Weighting
---

- Start by fixing the values for evidence variables
- Sample the non-evidence variables using conditional probabilities in the Bayesian Network
- Weight each sample by its **likelihood**: the probability of all the evidence

### Uncertainty over Time
---

- **Markov assumption**: the assumption that the current state depends on only a finite fixed number of previous states
- **Markov chain**: a sequence of random variables where the distribution of each variable follows the Markov assumption
- **Transition model**: can be represented as Matrix for transitioning a distribution from one timestep to the next
- **Hidden Markov model**: a Markov model for a system with hidden states that generate some observed event
- **Sensor Markov assumption**: the assumption that the evidence variable depends only (on) the corresponding state

#### Task definitions
---

| Task | Definition |
|:-----|:-----------|
| filtering | given observations from start until now, calculate distribution for **current** state |
| prediction | given observations from start until now, calculate distribution for a **future** state |
| smoothing | given observations from start until now, calculate distribution for **past** state |
| most likely explanation | given observations from start until now, calculate most likely **sequence** of states |

## Optimization
---

### Local Search
---

- search algorithms that maintain a single node and serches by moving to a neighboring node
- state-space landscape (where the nodes are on x, and the objective/cost function on y)

#### Hill Climbing (pseudocode)
---

```python
def hill_climb(problem):
    current = initial_state_of_problem
    repeat:
        neighbor = highest_valued_neighbor(current)
        if neighbor not better than current:
            return current
        current = neighbor
```

#### Hill Climbing Variants
---

| Variant | Definition |
|:--------|:-----------|
| steepest-ascent | choose the highest-valued neighbor |
| stochastic | choose randomly from higher-valued neighbors |
| first-choice | choose the first higher-valued neighbor |
| random-restart | conduct hill climbing multiple times |
| local beam search | chooses the *k* highest-valued neighbors |

#### Simulated Annealing
---

- Early on, higher "temperature": more likely to accept neighbors that are worse than current state
- Later on, lower "temperature": less likely to accept neighbors that are worse than current state

Pseudocode
```python
def simulated_annealing(problem, max):
    current = initial_state_of_problem
    for t = 1 to max:
        T = temperature(t)
        neighbor = random_neighbor(current)
        delta_E = how much better neighbor is than current
        if delta_E > 0:
            current = neighbor
        with probability exp(delta_E/T) set current = neighbor
    return current
```

### Linear Programming 
---

- minimize a linear cost function $ c_1 x_1 + c_2 x_2 + ... + c_n x_n $
- with constraints of form $ a_1 x_1 + a_2 x_2 + ... + a_n x_n \leq b $
- with bounds for each variable $ l_i \leq x_i \leq u_i $

Linear Programming Algorithms
- Simplex
- Interior-Point

### Constraint Satisfaction
---

#### Terminology
---

- Set of variables $ \lbrace X_1, X_2, ..., X_n \rbrace $
- Set of domains for each variable $ \lbrace D_1, D_2, ..., D_n \rbrace $
- Set of constraints $ C $
- **hard constraints**: constraints that must be satisfied in a correct solution
- **soft constraints**: constraints that express some notion of which solutions are preferred over others
- **unary constraint**: constraint involving only one variable (e.g. $ \lbrace A \neq Monday \rbrace $)
- **binary constraint**: constraint involving two variables (e.g. $ \lbrace A \neq B \rbrace $)
- **node consistency**: when all the values in a variable's domain satisfy the variable's **unary** constraints
- **arc consistency**: whenn all the values in a variable's domain satisfy the variables's **binary** constraints
  - To make $ X $ arc-consistent with respect to $ Y $, remove elements from $ X $'s domain until every choice for $ X $ has a possible choice for $ Y $

#### Arc Consistency (pseudocode)
---

```python
def revise(csp, X, Y):
    revised = False
    for x in X.domain:
        if no y in Y.domain satisfies constraint for (X, Y):
            delete x from X.domain
            revised = True
    return revised
```

#### CSP as Search Problems
---

- **initial state**: empty assignment (no variables)
- **actions**: add a $ \lbrace variable = value \rbrace $ to assignment
- **transition model**: shows how adding an assignment changes the assignment
- **goal test**: check if all variables assigned and constraints all satisfied
- **path cost functions**: all paths have same cost

#### Maintaining arc-consistency
---

- algorithm for enforcing arc-consistency every time we make a new assignment
- When we make a new assignment to $ X $, calls AC-3, starting with a queue of all arcs $ (X, Y) $ where $ Y $ is a neighbor of $ X $

Pseudocode
```python
def ac_3(csp):
    queue = all arcs in csp
    while queue non-empty:
        (X, Y) = dequeue(queue)
        if revise(csp, X, Y):
            if size of X.domain == 0:
                return False
            for each Z in X.neighbors - {Y}:
                enqueue(queue, (Z, X))
    return true
```

#### Backtracking Search (pseudocode)
---

```python
def backtrack(assignment, csp):
    if assignment complete: return assignment
    var = select_unassigned_var(assignment, csp)
    for value in domain_values(var, assignment, csp):
        if value consistent with assignment:
            add {var = value } to assignment
            result = backtrack(assignment, csp)
            if result != failure: return result
        remove {var = value} from assignment
    return failure
```

#### Backtracking Search with Inference (pseudocode)
---

```python
def backtrack(assignment, csp):
    if assignment complete: return assignment
    var = select_unassigned_var(assignment, csp)
    for value in domain_values(var, assignment, csp):
        if value consistent with assignment:
            add {var = value } to assignment

            inferences = Inference(assignment, csp)
            if inferences != failure: add inferences to assignment
            
            result = backtrack(assignment, csp)
            if result != failure: return result
                
        remove {var = value} and inferences from assignment
        
    return failure
```

##### Heuristics
---

**select_unassigned_var()**
- **minimum remaining values (MRV)** heuristic: select the variable that has the smallest domain
- **degree** heuristic: select the variable that has the highest degree

**domain_values**
- **least_constraining values** heuristic: return variables in order by number of choices that are ruled out for neighboring variables
  - try least-constraining values first

## Learning
---

### Terminology
---

- **Supervised learning**: given a data set of input-output pairs, learn a function to map inputs to outputs
- **Unsupervised learning**: given input data without any additional feedback, learn patterns
- **Classification**: supervised learning task of learning a function mapping an input point to a discrete category
  - **nearest-neighbor classification**: algorithm that, given an input chooses the class of the nearest data point to that input
  - *k* **-nearest-neighbor classification**: algorithm that, given an input chooses the class out of the *k*-nearest data points to that input
- **maximum margin seperator**: boundary that maximizes the distance between any of the data points
- **clustering**: organizing a set of objects into groups in such a way that similar objects tend to be in the same group
  - *k* **-means clustering**: algorithm for clustering data based on repeatedly assigning points to clusters and updating those clusters' centers
- **regression**: supervised learning task of learning a function mapping an input point to a continuous value
- **loss function**: function that expresses how poorly our hypothesis performs
  - **0-1 loss function**: $ L(actual, predicted) = \begin{cases} 0 &\text{if } actual = predicted \\ 1 &\text{otherwise} \end{cases} $
  - $ L_1 $**loss function**: $ L(actual, predicted) = | actual - predicted | $
  - $ L_2 $**loss function**: $ L(actual, predicted) = ( actual - predicted )^2 $
- **overfitting**: a model that fits too closely to a particular data set and therefore may fail to generalize to future data
- **regularization**: penelaizing hypotheses that are more complex to favor simpler, more general hypotheses $ cost = loss(h) + \lambda complexity(h) $
- **holdout cross-validation**: splitting data into a **training set** and a **test set**, such that learning happens on the training set and is evaluated on the test set
  - *k* **-fold cross-validation**: splitting data into *k* sets, and experimenting *k* times, using each set as a test set once, and using remaining data as training set

### Reinforcment learning
---

Given a set of rewards or punishments, learn what actions to take in future

**Markov Decision Process**: model for decision-making, representing states, actions, and their rewards
  - Set of states $ S $
  - Set of actions $ Actions(s) $
  - Transition model $ P(s'|s, a) $
  - Reward function $ R(s, a, s') $

**Q-Learning**: method for learning a function $ Q(s, a) $, estimate of the value of performing action $ a $ in state $ s $
- Start with $ Q(s, a) = 0 $ for all $ s, a $
- When we taken an action and receive a reward:
   - Estimate the value of $ Q(s, a) $ based on current reward and expected future rewards
   - Update $ Q(s, a) $ to take into account old estimate as well as our new estimate

- Every time we take an action $ a $ in state $ s $ and observe a reward $ r $, we update:

$$ Q(s, a) \leftarrow Q(s, a) + \alpha(\text{new value estimate} - \text{old value estimate}) $$
$$ \iff Q(s, a) \leftarrow Q(s, a) + \alpha(\text{new value estimate} - Q(s, a)) $$
$$ \iff Q(s, a) \leftarrow Q(s, a) + \alpha((r + \text{future reward estimate}) - Q(s, a)) $$
$$ \iff Q(s, a) \leftarrow Q(s, a) + \alpha((r + max_{a'} Q(s', a')) - Q(s, a)) $$
$$ \iff Q(s, a) \leftarrow Q(s, a) + \alpha((r + \gamma max_{a'} Q(s', a')) - Q(s, a)) $$

- **greedy decision-making**: when in state $ s $, choose action $ a $ with highest $ Q(s, a) $
- $ \epsilon $ **-greedy**
  - Set $ \epsilon $ to how often we want to move randomly
  - With probability $ 1 - \epsilon $, choose estimated best moe
  - With probability $ \epsilon $, choose a random move
- **function approximation**: approximating $ Q(s, a) $, often by a function combining various features, rather than storing one value for every state-action pair

## Neural Networks
---

### Perceptron
---

Perceptron learning rule
- given a data point $ (x, y) $, update each weight according to: $$ w_i = w_i + \alpha (y - h_w(x)) \times x_i $$
- given a data point $ (x, y) $, update each weight according to: $$ w_i = w_i + \alpha (Actual Value - Estimate) \times x_i $$
- only capable of learning lineary separable decision boundary

Given a vector $ X $ as input and a vector $ W $ representing weights

$$ \hat y = g(w_0 + X^T W) $$

thus 

$$ z = w_0 + \sum_{j = 1}^{m} x_j w_j $$

and
$$ y = g(z) \text{ with non-linear } g(x) \mapsto y $$

### Backpropagation
---

Start with a random choice of weights
- Repeat:
  - Calculate error for output layer
  - For each layer, starting with output layer, and moving inwards towards earliest hidden layer:
    - Propagade error back one layer
    - Update weights

### Gradient Descent
---

- algorithm for minimizing loss when training neural networks
  - Start with a random choice of weights
  - Repeat:
    - Calculate the gradient based on all data points (direction that will lead to decreasing loss)
    - Update weights according to the gradient

#### Stochastic Gradient Descent (SGD)
---

$$ w_{new} = w - \eta \nabla_w L $$

with
- $ \eta \coloneqq $ learning rate
- $ \nabla_w L \coloneqq $ Gradient of Loss in respect to $ w $

#### SGD with Momentum
---

$$ w_{new} = w + \gamma v - \eta \nabla_w L $$

with
- $ \gamma \coloneqq $ factor to retain velocity (typically $ \backsimeq $ 0.9) 

#### Adaptive Gradient (AdaGrad)
---

$$ w_{new} = w - \frac{\eta}{\sqrt{G_t + \epsilon}} \nabla_w L $$

with
- $ G_t \coloneqq $ Sum of squares of past Gradients
- $ \epsilon \coloneqq $ const $ \backsimeq $ 0 to prevent zero-division

#### RMSprop
---

$$ G_t = \beta G_t + (1 - \beta)(\nabla_w L)^2 $$
$$ w_{new} = w - \frac{\eta}{\sqrt{G_t + \epsilon}} \nabla_w L $$

with
- $ \beta \coloneqq $ decay rate (typically $ \backsimeq $ 0.9) controlling influence of past Gradients

#### Adam (Adaptive movement estimation)
---

Combination of Momentum & RMSprop

$$ m_t = \beta_1 m_{t - 1} + (1 - \beta_1) \nabla_w L $$
$$ v_t = \beta_2 v_{t - 1} + (1 - \beta_2) (\nabla_w L)^2 $$

with
- $ m_t \coloneqq $ moving average of grad (momentum term)
- $ v_t \coloneqq $ moving average of squared grad (RMSprop term)

Avoiding initial bias
$$ \hat m_t = \frac{m_t}{1 - b_{1}^t} \text{ ; } \hat v_t = \frac{v_t}{1 - b_{2}^t} $$

thus
$$ w_{new} = w - \frac{\eta}{\sqrt {\hat v_t} + \epsilon} \hat m_t $$

### Dropout
---

- temporarily removing units - *selected at random* - from a neural network to prevent over reliance on certain units

### Computer Vision
---

- **image convolution**: applying a filter that adds each pixel value of an image to its neighbors, weighted according to a kernel matrix
- **pooling**: reducing the size of an input by a sampling from regions in the input
  - **max-pooling**: pooling by choosing the maximum value in each region

# Suffix
---

*Section yet to be written...*
